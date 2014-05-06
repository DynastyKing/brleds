#include "constants.h"

#ifndef COMPRESSION_FUNCTION_H
#define COMPRESSION_FUNCTION_H 1

// Constants for array references
#define INIT_WORDS 25
#define CHUNK_WORDS 16
#define CFBUF_WORDS (INIT_WORDS + 4*CHUNK_WORDS)
#define MAX_KEYLEN 64

/* Bitwise rotation operations*/
uint64 rr(uint64 x, short offset);
uint64 rl(uint64 x, short offset);

/* Round recurrence calculator */
uint64 next_s(uint64 s);
uint64 nth_next_s(uint64 s, int n);

/* Intra-word diffusion function */
uint64 g(uint64 x, short r, short l);

/* MD6's compression function.
   f expects you to allocate buf with space for at least CFBUF_WORDS uint64s. 
   f destroys the contents of buf and returns its value in dst, which must
   have space for at least CHUNK_WORDS uint64s. */
void f(uint64* buf, uint64* dst, int r);

/* Miscellaneous utilities */
// Like normal division, except it ceils instead of floors at the end
uint64 divide_and_ceil(uint64 numerator, uint64 denominator);
uint64 min(uint64 x, uint64 y);
// print out the contents of a buffer.
void print_buf(uint64* buf, int num);

#endif /* COMPRESSION_FUNCTION_H */
