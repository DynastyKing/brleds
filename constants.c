#include "constants.h"

// Debug flag
int debug = 0;

// Compression function constants //////////////////////////
/* Shift amounts */
short r_shift[] = {10,  5, 13, 10, 11, 12,  2,  7,
		   14, 15,  7, 13, 11,  7,  6, 12};
short l_shift[] = {11, 24,  9, 16, 15,  9, 27, 15,
		   6,  2,  29,  8, 15,  5, 31,  9};

/* Tap positions */
short tap[] = {17, 18, 21, 31, 67};

/* Round constant recurrence info */
uint64 s_init = 0x0123456789abcdef;
uint64 s_recur = 0x7311c2812425cfa0;

int steps_per_round = 16;

// Mode of operation constants /////////////////////////////////
uint64 q_constant[] = {
  0x7311c2812425cfa0,
  0x6432286434aac8e7,
  0xb60450e9ef68b7c1,
  0xe8fb23908d9f06f1,
  0xdd2e76cba691e5bf,
  0x0cd0d63b2c30bc41,
  0x1f8ccf6823058f8a,
  0x54e5ed5b88e3775d,
  0x4ad12aae0a6d6031,
  0x3e7f16bb88222e0d,
  0x8af8671d3fb50c2c,
  0x995ad1178bd25c31,
  0xc878c1dd04c4b633,
  0x3b72066c7a1552ac,
  0x0d6f3522631effcb,
  0x8b30ed2e9956c6a0,
  0x34a3a6be63e016c2,
  0xe900badfdbd4b2fe,
  0xee3bdab2deb625cb,
  0xe03176c8139ebfb3,
  0xc02562aba049daa2,
  0x7c088ace48307b74,
  0xd418e9a73867fd13,
  0x7be1ed9961b81d25,
  0x2c1c64f56a4fa052,
  0x5665a0851aeeea55,
  0xa9d17677c269f50c,
  0xc58fcffdc90adf1b,
  0xe38ae2b5d4e6c17c,
  0x9db4279c70f5b277,
  0xfff6357a07c77776,
  0x2a05e98194256d9d
};

int q_len = 15; // in words

