#ifndef MD6_MODES_H
#define MD6_MODES_H 1

#include "constants.h"
#include "compression_function.h"


struct md6_config
{
  uint8 key[MAX_KEYLEN]; // key used for initialization. must be filled in to a 64-bit boundary
  uint8 keylen;          // length of the original key, in bytes
  uint16 rounds;         // number of rounds in the compression function (12-bit limit) 
  uint8 max_level;       // maximum tree level 
  uint16 digest_size;    // length in bits of desired hash output (1-512)  
};

// Computes MD6 on the specified message with the specified configuration
// options. Places the message digest in output, which must be
// at least 16 words long.
void md6(uint64* message, uint64 len,
	 struct md6_config* config, uint64* output);

// Reverses the byte order of the given value. 
uint64 reverse_byte_order(uint64 value);
// Reverses the byte order of all of the uint64's in the provided buf
void reverse_buffer_byte_order(uint64* buf, int len);
// "truncates" the buffer by zeroing out all but the final num_bits
void truncate_buf(uint64* buf, uint64 num_bits, uint64 buf_len);

//////////////////////////////////////////////////////////////
// These are exposed solely for testing purposes

// Fill in buf with md6 constants / control words
void initialize_buf(uint64* buf, struct md6_config* config,
		    uint8 z, uint16 num_padding_bits, 
		    uint8 current_level, uint64 level_index);


// Run md6's PAR mode of operation
void par(uint64* message, uint64 len, 
	 struct md6_config* config, uint64* output,
	 uint8 current_level, uint64 current_index,
	 uint8 finalize);

// Run md6's SEQ mode of operation
void seq(uint64* message, uint64 len, 
	 struct md6_config* config, uint64* output);

#endif /* MD6_MODES_H */
