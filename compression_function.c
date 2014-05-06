#include "constants.h"
#include "compression_function.h"
#include <stdio.h>

/* Bitwise rotation operations*/
uint64 rr(uint64 x, short offset) {
  return (x >> offset) | (x << (64 - offset));
}

uint64 rl(uint64 x, short offset) {
  return (x << offset) | (x >> (64 - offset));
}

/* Round recurrence calculator */
uint64 next_s(uint64 s) {
  return rl(s, 1) ^ (s & s_recur);
}

uint64 nth_next_s(uint64 s, int n) {
  for(;n > 0; n--) {
    s = next_s(s);
  }
  return s;
}

/* Intra-word diffusion function */
uint64 g(uint64 x, short r, short l) {
  uint64 y;
  y = x ^ (x >> r);
  return y ^ (y << l);
}

/* f expects you to allocate buf with space for at least CFBUF_WORDS uint64s.
   f destroys the contents of buf and returns its value in dst, which must
   have space for at least CHUNK_WORDS uint64s. */
void f(uint64* buf, uint64* dst, int r) {
  uint64 new_val;
  uint64 s = s_init;
  int i;
  int final_index = (r * steps_per_round) + CFBUF_WORDS;
  if (debug >= 2) {
    printf("running f\ninput:");
    print_buf(buf, CFBUF_WORDS);
  }

  for(i = CFBUF_WORDS; i < final_index; i++) {
    if (i > CFBUF_WORDS && (i - CFBUF_WORDS) % steps_per_round == 0) {
      s = next_s(s);
    }
    // Compute one round of f, treating buf as a circular buffer.
    new_val = s ^ buf[i%CFBUF_WORDS] ^ buf[(i - tap[0])%CFBUF_WORDS];
    new_val = new_val ^ (buf[(i - tap[1])%CFBUF_WORDS] & buf[(i - tap[2])%CFBUF_WORDS]) ^
                        (buf[(i - tap[3])%CFBUF_WORDS] & buf[(i - tap[4])%CFBUF_WORDS]);
    new_val = g(new_val,
		r_shift[(i - CFBUF_WORDS)%steps_per_round],
		l_shift[(i - CFBUF_WORDS)%steps_per_round]);
    buf[i%CFBUF_WORDS] = new_val;

    if (debug >= 3) {
      printf("A[%4d] = %016llx\n", i, new_val);
    }
  }

  // After all the rounds are complete, the final 16 bytes of buf are
  // the output. Copy the output to dst.
  for(i = 0; i < CHUNK_WORDS; i++) {
    dst[i] = buf[(final_index - CHUNK_WORDS + i)%89];
    if (debug >= 2) {
      printf("O[%2d] = %016llx\n", i, dst[i]);
    }
  }
}

uint64 divide_and_ceil(uint64 numerator, uint64 denominator) {
  uint64 result = numerator / denominator;
  if (numerator % denominator != 0) {
    result += 1;
  }
  return result;
}

uint64 min(uint64 x, uint64 y) {
  if (x < y) {
    return x;
  }
  return y;
}

void print_buf(uint64* buf, int num) {
  int i;
  printf("  ");
  for (i = 0; i < num; i++) {
    printf("%04d: %016llx \n", i, buf[i]);
    /*    if (i %4 == 3) {
      printf("\n  ");
      }*/
  }
  printf("\n");
}
