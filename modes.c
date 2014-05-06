#include "compression_function.h"
#include "modes.h"
#include "constants.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>


int md6_default_r(int d, int keylen)
{

  int r;
  r = 40 + d/4;
  if (keylen > 0) {
    if (r < 80) {
      r = 80;
    }
  }
  return r;
}

// Set up buf with the 25 bytes of initialization
void initialize_buf(uint64* buf, struct md6_config* config,
		    uint8 z, uint16 num_padding_bits,
		    uint8 current_level, uint64 level_index) {
  uint64 v;
  uint64 u;

  // Compose control word U
  u = current_level;
  u <<= 56;
  u = u | (level_index & 0x00ffffffffffffff);

  // Compose control word V
  v = config->rounds & 0x0fff;
  v <<= 8;
  v = v | config->max_level;
  v <<= 4;
  v = v | (z & 0x01);
  v <<= 16;
  v = v | num_padding_bits;
  v <<= 8;
  v = v | config->keylen;
  v <<= 12;
  v = v | (config->digest_size & 0x0fff);

  memcpy(buf, &q_constant, q_len*sizeof(uint64));
  // config->key is copied up to a 64-bit boundary
  // in order to deal with the little / big endian issue.
  // (b/c converting here doesn't seem reasonable).
  memcpy(&(buf[15]), &(config->key), 8*divide_and_ceil(config->keylen, 8));
  memset( ((uint8 *)(buf)) + sizeof(uint64)*15 +  8*divide_and_ceil(config->keylen, 8),
	  0, MAX_KEYLEN -  8*divide_and_ceil(config->keylen, 8));
  buf[23] = u;
  buf[24] = v;
}

/* len is in bits */
void par(uint64* message, uint64 len,
	 struct md6_config* config, uint64* output,
	 uint8 current_level, uint64 current_index,
	 uint8 finalize) {

  uint64 buf[CFBUF_WORDS];
  // message_size is how big the message should be at the current level
  // (in bits)
  uint64 message_size =  1 << (10 + 2*current_level);
  uint64 padding;
  uint64 size;
  int i;

  if (debug) {
    printf("calling par. len: %lld. (%d, %lld) \n", len, current_level, current_index);
  }

  if (current_level == 1) {
    padding = message_size - len;
    initialize_buf(buf, config, finalize, padding, current_level, current_index);
    memset(&(buf[INIT_WORDS]), 0, sizeof(uint64)*CHUNK_WORDS*4);

    // this assumes message is padded with zeros up to a 64-bit boundary
    memcpy(&(buf[INIT_WORDS]), message, divide_and_ceil(len,64)*sizeof(uint64));
    f(buf, output, config->rounds);
  } else {

    // Padding can only be a multiple of (0-3)*CHUNK_WORDS * 64, because the
    // recursive par operations always return CHUNK_WORDS * 64 bits
    padding = CHUNK_WORDS*64*(4 - divide_and_ceil(len, message_size/4));

    // Set up initialization constants and padding
    initialize_buf(buf, config, finalize, padding, current_level, current_index);
    memset(&(buf[INIT_WORDS]), 0, sizeof(uint64)*CHUNK_WORDS*4);

    for (i = 0; i < divide_and_ceil(len, message_size/4); i++) {
      // size is always message_size/4 except for on the last iteration,
      // when it's whatever is left of the message
      size = min(message_size/4, len - i*(message_size/4));
      par(&(message[i*(message_size/(4*64))]), size, config, &(buf[INIT_WORDS + i*CHUNK_WORDS]),
	  current_level - 1, 4*current_index + i, 0);
    }
    f(buf, output, config->rounds);
  }
}

// message is assumed to be padded with 0s until a 64-bit word boundary.
void seq(uint64* message, uint64 len,
	 struct md6_config* config, uint64* output) {

  uint64 i;
  uint64 buf[CFBUF_WORDS];
  uint64 chain[CHUNK_WORDS];
  uint64 num_words;

  if (debug) {
    printf("Running SEQ. message (%d bits):\n", len);
    //print_buf(message, divide_and_ceil(len, 64));
  }

  // Buf is the chaining variable. IV is all 0s
  memset(chain, 0, CHUNK_WORDS*sizeof(uint64));

  // SEQ reads 3 chunks at a time from the input,
  // and each chunk is 16 * 64 = 1024 bits long.
  // Loop over complete 3-chunk segments
  for(i = 0; (i*(CHUNK_WORDS * 64 * 3) < len) || i == 0 ; i++) {
    if ((i+1)*(CHUNK_WORDS * 64 * 3) >= len) {
      // The last round has z set to 1, and also means
      // that message may require padding.

      // Compute the number of words to copy
      num_words = divide_and_ceil(len - (i * CHUNK_WORDS * 64 * 3), 64);

      memset(&(buf[INIT_WORDS + CHUNK_WORDS]), 0, sizeof(uint64)*CHUNK_WORDS*3);
      // I'm assuming here that message is going to be padded with
      // 0s up to a 64-bit boundary (i.e. if len % 64 != 0,
      // then the (len/64 + 1)st word of message will be padded with zeros)
      memcpy(&(buf[INIT_WORDS + CHUNK_WORDS]),
	     &(message[i * CHUNK_WORDS * 3]),
	     num_words*sizeof(uint64));

      // Set up configuration, setting finalization bit and padding
      initialize_buf(buf, config, 1, ((i+1)*CHUNK_WORDS * 64 * 3) - len, config->max_level + 1, i);
      if (debug) {
	printf("(final round. padding %d bits) ", ((i+1)*CHUNK_WORDS * 64 * 3) - len);
      }

    } else {
      // Set up standard configuration variables
      initialize_buf(buf, config, 0, 0, config->max_level + 1, i);
      // Not the last message, so it's safe to copy
      // CHUNK_WORDS * 3 words from message.
      memcpy(&(buf[INIT_WORDS + CHUNK_WORDS]),
	     &(message[i * CHUNK_WORDS * 3]),
	     sizeof(uint64)*CHUNK_WORDS*3);
    }

    // Put in the chaining variable
    memcpy(&(buf[INIT_WORDS]), chain, CHUNK_WORDS*sizeof(uint64));

    if (debug) {
      printf("Round (%d, %d):\n", config->max_level + 1, i);
      print_buf(buf, CFBUF_WORDS);
    }

    // Compute compression function
    f(buf, chain, config->rounds);

    if (debug) {
      printf("output var:\n");
      print_buf(chain, CHUNK_WORDS);
    }
  }

  // Return the whole output chunk
  memcpy(output, chain, CHUNK_WORDS*sizeof(uint64));
}


void truncate_buf(uint64* buf, uint64 num_bits, uint64 buf_len) {
  // buf_len is in words!
  uint64 i;

  // Zero out all bits before the words required for the digest
  memset(buf, 0, (buf_len - divide_and_ceil(num_bits, 64))*sizeof(uint64));

  buf[buf_len - divide_and_ceil(num_bits,64)] &= (0xffffffffffffffff >> (64 - (num_bits %64)));
}

void md6(uint64* message, uint64 len,
	 struct md6_config* config, uint64* output) {
  int i;
  uint8 levels = 0;
  uint64 par_tree_size;
  uint64 num_chunks;
  uint64 size;
  uint64* buf;

  // Adjust input to host byte order
  reverse_buffer_byte_order(message, divide_and_ceil(len, 64));

  // handle L = 0 (SEQ) case first:
  if (config->max_level == 0) {
    seq(message, len, config, output);
    truncate_buf(output, config->digest_size, CHUNK_WORDS);
    // Convert back to network order.
    reverse_buffer_byte_order(output, CHUNK_WORDS);
    return;
  }

  // figure out how many levels of the tree we have to build.
  for(levels = 1; len > (1 << (10 + 2*levels)); levels++)
    ;

  // run in PAR mode if possible
  if (levels <= config->max_level) {
    par(message, len, config, output, levels, 0, 1);
    truncate_buf(output, config->digest_size, CHUNK_WORDS);
    // Convert back to network order.
    reverse_buffer_byte_order(output, CHUNK_WORDS);
    return;
  }

  // Have to run in both PAR and SEQ modes.

  // Allocate temporary space to store the results of the initial PAR
  // operations.

  // Each PAR tree contains 1024 * 4^L bits
  par_tree_size = (1 << (10 + 2*config->max_level));
  num_chunks = divide_and_ceil(len, par_tree_size);
  buf = (uint64*) malloc(num_chunks*CHUNK_WORDS*sizeof(uint64));

  for(i = 0; i < num_chunks; i++) {
    size = min(par_tree_size, len - i*par_tree_size);
    par(&(message[i*(par_tree_size / 64)]),
	size, config, &(buf[i*CHUNK_WORDS]), config->max_level,
	i, 0);
  }

  seq(buf, num_chunks * CHUNK_WORDS * 64, config, output);
  truncate_buf(output, config->digest_size, CHUNK_WORDS);
  // Convert back to network order.
  reverse_buffer_byte_order(output, CHUNK_WORDS);
  free(buf);
}

void reverse_buffer_byte_order(uint64* buf, int len) {
  int i;
  for (i = 0; i < len; i++) {
    buf[i] = reverse_byte_order(buf[i]);
  }
}

uint64 reverse_byte_order(uint64 value) {
  uint64 temp;
  int i;
  for (i = 0; i < 8; i++) {
    ((char*)&temp)[i] = ((char*)&value)[7 - i];
  }
  return temp;
}
