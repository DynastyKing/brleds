#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "constants.h"
#include "modes.h"
#include "nist.h"

void parse_key(char* key, struct md6_config* config);
void parse_args(int argc, char* argv[], struct md6_config* config);
void print_output(uint64* output, uint16 digest_size);

int main (int argc, char* argv[]) {

  // There are some potential endian-ness issues here,
  // since md6 is big endian and I'm writing on a little endian computer.
  // I *think* the initial conversion from a char[] to uint64[] that flips the
  // byte order within every 64-bit word solves the problem.

  hashState state;
  uint64* message;
  uint64 output[CHUNK_WORDS];
  uint64 num_bytes_read;
  int max_input_size;
  int i, shift;
  uint8 cur_byte;

  // Initialize the hash state, but then override the md6_config parameters
  // to allow the user to set the optional parameters.
  Init(&state, 0);

  parse_args(argc, argv, &(state.config));

  if (debug) {
    printf("Running md6. d: %d, l: %d, r: %d \n",
	   state.config.digest_size, state.config.max_level, state.config.rounds);
    printf("key (%d bytes):\n", state.config.keylen);
    print_buf((uint64 *)state.config.key, divide_and_ceil(state.config.keylen,8));
  }

  // Having a fixed size for message is totally wrong.
  // All modes of operation should operate on streams (e.g. file
  // descriptors) instead of strings.
  // This is easier to get correct, however.
  max_input_size = 10*1024*1024;
  message = malloc(max_input_size);
  memset(message, 0, max_input_size);

  while(num_bytes_read = read(0, message, max_input_size)) {
    if (debug) {
      printf("read %d bytes \n", num_bytes_read);
    }
    Update(&state, message, num_bytes_read*8);
  }

  Final(&state, output);

  printf("digest (%d bits): \n", state.config.digest_size);
  print_output(output, state.config.digest_size);

  /*
  // non-NIST compatible md6 interface
  md6(message, num_bytes_read*8, &(state.config), output);
  // md6 reverses the input byte order of the message...
  reverse_buffer_byte_order(message, num_bytes_read/8);


  printf("digest (%d bits): \n", state.config.digest_size);
  print_output(output, state.config.digest_size);
  printf("\n\n");
  */

  free(message);
  return 0;
}

void print_output(uint64* output, uint16 digest_size) {
  int i;
  int shift;
  uint8 cur_byte;

  // Output is printed in hex with config.digest_size / 8 bytes.
  // Compute a shift to move any 0 padding to the end.
  shift = (8 - (digest_size%8));
  if (shift == 8) {
    shift = 0;
  }

  for (i = (1024 - digest_size)/8; i < 128; i++) {
    cur_byte = ((uint8 *)output)[i] << shift;
    if (i+ 1 < 128) {
      cur_byte |= ((uint8 *)output)[1 + i] >> (8 - shift);
    }
    printf("%02x", cur_byte);
  }
}

void parse_args(int argc, char* argv[], struct md6_config* config) {
  int i;
  int num_rounds = -1;

  // Set default parameters:
  config->keylen = 0; // implies key is nil
  memset(config->key, 0, MAX_KEYLEN);
  config->max_level = 64;
  config->digest_size = 0; // This must be specified!
  config->rounds = 104;    // Determined from digest size

  for(i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-k") == 0 ||
	strcmp(argv[i], "--key") == 0) {
      parse_key(argv[i+1], config);
      i++;
    } else if (strcmp(argv[i], "-d") == 0 ||
	       strcmp(argv[i], "--digest-size") == 0) {
      config->digest_size = atoi(argv[i + 1]);
      i++;
    } else if (strcmp(argv[i], "-L") == 0 ||
	       strcmp(argv[i], "--level") == 0) {
      config->max_level = atoi(argv[i + 1]);
      i++;
    } else if (strcmp(argv[i], "-r") == 0 ||
	       strcmp(argv[i], "--rounds") == 0) {
      num_rounds = atoi(argv[i + 1]);
      i++;
    } else if (strcmp(argv[i], "-i") == 0) {
      debug = atoi(argv[i + 1]);
    } else if (strcmp(argv[i], "-h") == 0 ||
	       strcmp(argv[i], "--help") == 0) {
      printf("\nmd6 usage: \n");
      printf("md6 -d <digest_size> < <filename>\n");
      printf("\nOptions:\n");
      printf("-k, --key <key>        Use <key> in the compression function\n");
      printf("-L, --level <level>    Specify the maximum level for PAR operation\n");
      printf("-r, --rounds <rounds>  Run the compression function for <rounds>\n");
      printf("-i <debug level>       How much debug output. 0 is least, 2 is most\n");
      printf("-h, --help             Print this help and exit\n\n");
      exit(0);
    }
  }

  if (num_rounds != -1) {
    config->rounds = num_rounds;
  } else {
    config->rounds = md6_default_r(config->digest_size, config->keylen);
  }

  if (config->digest_size < 1 || config->digest_size > 512) {
    printf("digest size must be between 1 and 512 (inclusive)\n\n");
    exit(1);
  } else if (config->rounds > 0x0fff) {
    printf("rounds must be between 1 and %d (inclusive)\n\n", 0x0fff);
  }
}

void parse_key(char* key, struct md6_config* config) {
  int i;

  // Make sure key is an appropriate size
  config->keylen = strlen(key);
  if (config->keylen > MAX_KEYLEN) {
    printf("key must be between 1 and 64 bytes.\n\n");
    exit(1);
  }
  // Copy the key into the md6_config struct,
  // converting from big endian to little endian.
  for (i = 0; i < config->keylen; i++) {
    // index in argv to avoid array out of bounds.
    // config->key has already been zeroed out,
    (config->key)[8*(i/8) + 7 - (i % 8)] = key[i];
  }
  // Add zero bytes to finish off the key.
  for (;i % 8 != 0; i++) {
    (config->key)[8*(i/8) + 7 - (i % 8)] = 0;
  }
}


