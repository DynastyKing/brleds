#include "nist.h"
#include "modes.h"
#include "constants.h"
#include <stdio.h>

HashReturn Init( hashState *state,
		 int hashbitlen
		 ) {
  if (debug) {
    printf("running Init\n");
  }

  // Initialize md6 configuration
  memset(state->config.key, 0, MAX_KEYLEN);
  state->config.keylen = 0;
  state->config.max_level = 64;
  state->config.digest_size = hashbitlen;
  // Default round length is 40 + floor(d/4), unless keylen > 0,
  // in which case the number of rounds must be at least 80.
  state->config.rounds = 40 + (state->config.digest_size / 4);
  state->num_levels = 0;
}

void md6_update(hashState *state,
		const BitSequence *data,
		DataLength databitlen,
		int level) {

  int bits_consumed = 0;
  int copy_amount = 0;
  levelState* cur_level;
  uint64 output[CHUNK_WORDS];
  cur_level = &(state->levels[level]);

  // Update the maximum level counter
  if (state->num_levels < level) {
    state->num_levels = level;
  }

  // SEQ special case: Initialize the first chaining variable
  if (level == state->config.max_level + 1 &&
      cur_level->index == 0 &&
      cur_level->numbits == 0) {
    memset(&(cur_level->buf[25]),
	   0,
	   CHUNK_WORDS*sizeof(uint64));
    cur_level->numbits += CHUNK_WORDS*sizeof(uint64)*8;
  }

  if (debug) {
    printf("Update with %d bits\n", databitlen);
  }
  while (bits_consumed < databitlen) {
    // 1. Copy over as many bits as possible to level 0,
    // updating numbits counter
    copy_amount = (4096 - cur_level->numbits);
    if (copy_amount > databitlen - bits_consumed) {
      copy_amount = databitlen - bits_consumed;
    }

    if (debug) {
      printf("Copying %d bits (%d, %d)\n", copy_amount, level, cur_level->index);
    }
    // Note: this assumes the data is always provided
    // as bytes
    memcpy(&(((uint8 *)cur_level->buf)[200 + cur_level->numbits/8]),
	   &(((uint8 *)data)[bits_consumed/8]),
	   copy_amount/8);

    cur_level->numbits += copy_amount;
    bits_consumed += copy_amount;

    // 2. If this level is full and more bits are left:
    // First run compression functions on levels above
    // this one to clear up space for the output, then
    // compress this block and place it one level higher
    // in the tree.
    // Go to step 1.
    // (This is the PAR mode of operation)
    if (cur_level->numbits == 4096 &&
	bits_consumed < databitlen) {

      if (debug) {
	printf("Compressing\n");
      }

      if (level == 1) {
	// The input bytes are provided in network order. Convert
	// them to host order before running md6.
	reverse_buffer_byte_order(&(cur_level->buf[25]), 4*CHUNK_WORDS);
      }

      // Run compression function
      initialize_buf(cur_level->buf, &(state->config),
		     0, 0, (uint8)level, cur_level->index);
      f(cur_level->buf, output, state->config.rounds);
      cur_level->index++;
      cur_level->numbits = 0;

      if (level <= state->config.max_level) {
	// PAR mode of operation:
	// recursively update
	md6_update(state, (BitSequence*)output,
		   (DataLength)1024, level + 1);
      } else {
	// SEQ mode of operation:
	// use output as chaining variable
	if (level == 1) {
	  // This is pretty silly, but md6_update expects level 1 input
	  // to be in network order.
	  reverse_buffer_byte_order(output, CHUNK_WORDS);
	}

	memcpy(&(cur_level->buf[25]),
	       output,
	       CHUNK_WORDS*sizeof(uint64));

	cur_level->numbits += CHUNK_WORDS*sizeof(uint64)*8;
      }
    }
  }
}

HashReturn Update( hashState *state,
		   const BitSequence *data,
		   DataLength databitlen
		   ) {
  if (debug) {
    printf("running Update\n");
  }

  // md6_update doesn't currently support bit length
  // updates.
  if (databitlen % 8 != 0) {
    return FAIL;
  }
  md6_update(state, data, databitlen, 1);
}

void md6_final(hashState* state, int level) {
  levelState* cur_level;
  uint64 output[CHUNK_WORDS];
  int final;

  cur_level = &(state->levels[level]);
  if (cur_level->numbits > 0 ||
      (level == 1 && cur_level->index == 0)) { // special case the null input

    final = 0;
    if (level == state->num_levels) {
      final = 1;
    }

    if (level == 1) {
      // The input bytes are provided in network order. Convert
      // them to host order before running md6.
      reverse_buffer_byte_order(&(cur_level->buf[25]), 4*CHUNK_WORDS);
    }

    // Before compressing, zero out the end of the buffer
    reverse_buffer_byte_order(&((cur_level->buf)[INIT_WORDS + cur_level->numbits/64]), 1);
    memset(&(((uint8 *)cur_level->buf)[INIT_WORDS*sizeof(uint64) + divide_and_ceil(cur_level->numbits, 8)]),
	   0,
	   sizeof(uint64)*89 - (sizeof(uint64)*INIT_WORDS + divide_and_ceil(cur_level->numbits, 8)));
    reverse_buffer_byte_order(&((cur_level->buf)[INIT_WORDS + cur_level->numbits/64]), 1);

    initialize_buf(cur_level->buf, &(state->config),
		   final, 4096 - cur_level->numbits,
		   (uint8)level, cur_level->index);
    f(cur_level->buf, output, state->config.rounds);

    if (final) {
      truncate_buf(output, state->config.digest_size, CHUNK_WORDS);
      // Convert the output back to network order
      reverse_buffer_byte_order(output, CHUNK_WORDS);
      memcpy(state->hash_final, output, CHUNK_WORDS*sizeof(uint64));
      return;
    }

    // We'll only reach this code in the PAR mode of operation.
    // If we ever run md6_final on a level running in SEQ mode,
    // the final flag will be set because the SEQ level number must equal
    // state->num_levels.
    md6_update(state, (BitSequence*)output,
	       (DataLength)1024, level + 1);
    md6_final(state, level + 1);
  }
}

HashReturn Final( hashState *state,
		  BitSequence *hashval
		  ) {
  if (debug) {
    printf("running Final\n");
  }

  // make sure that md6_update has been run at least once.
  md6_update(state, (BitSequence*) 0, (DataLength)0, 1);
  md6_final(state, 1);
  memcpy(hashval, state->hash_final, CHUNK_WORDS*sizeof(uint64));
}

HashReturn Hash( int hashbitlen,
		 const BitSequence *data,
		 DataLength databitlen,
		 BitSequence *hashval
		 ) {
  hashState state;

  Init(&state, hashbitlen);
  Update(&state, data, databitlen);
  Final(&state, hashval);
}
