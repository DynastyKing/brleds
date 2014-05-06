/*
 * Definitions of the NIST hash function required interface
 */

#ifndef MD6_NIST_H
#define MD6_NIST_H

#include "modes.h"

typedef unsigned char BitSequence;

typedef unsigned long long DataLength;

typedef enum { SUCCESS = 0, FAIL = 1, BAD_HASHLEN = 2 } HashReturn;

typedef struct {
  int index;
  int numbits;
  uint64 buf[89];
} levelState;

typedef struct {
  struct md6_config config;
  levelState levels[32];
  int num_levels;
  uint64 hash_final[16];
} hashState;


HashReturn Init( hashState *state, 
		 int hashbitlen
		 );

HashReturn Update( hashState *state, 
		   const BitSequence *data, 
		   DataLength databitlen
		   );

HashReturn Final( hashState *state,
		  BitSequence *hashval
		  );

HashReturn Hash( int hashbitlen,
		 const BitSequence *data,
		 DataLength databitlen,
		 BitSequence *hashval
		 );

#endif
