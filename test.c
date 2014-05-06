#define DEBUG 1

#include<stdio.h>
#include<stdlib.h>
#include<assert.h>
#include "modes.h"

void assert_buf_equal(uint64* buf1, uint64* buf2, int len) {
  int i;
  for(i = 0; i < len; i++) {
    printf("%d: %llx %llx \n", i, buf1[i], buf2[i]);
    assert(buf1[i] == buf2[i]);
  }
}

void test_rr() {
  assert(rr(0x0123456789abcdef, 4) == 0xf0123456789abcde);
  assert(rr(0x00011, 1) == 0x8000000000000008);
}

void test_rl() {
  assert(rl(0x0123456789abcdef, 8) == 0x23456789abcdef01);
  assert(rl(0x8800000000000000, 1) == 0x1000000000000001);
}

void test_s() {
  int i = 0;
  uint64 s = s_init;
  uint64 s_vals[] = {0x0123456789abcdef,
		     0x0347cace1376567e, 
		     0x058e571c26c8eadc, 
		     0x0a1cec3869911f38};

  for(i = 0; i < 4; i++) {
    printf("%d %llx\n", i, s);
    assert(s == s_vals[i]);
    s = next_s(s);
  }

  s = s_init;
  assert(nth_next_s(s, 1) == s_vals[1]);
  assert(nth_next_s(s, 3) == s_vals[3]);
}

void test_g() {
  assert(g(0x0123456789abcdef, 9, 22) == 0x306d4f03382f1809);
  assert(g(0x147abd8901234def, 17, 12) == 0xbf01f24a23302d7e);
  assert(g(0x0001000000008000, 16, 17) == 0x3000000008000);
}

void test_f() {
  int i = 0;
  uint64 s = s_init;
  uint64 buf[89];
  uint64 dst[16];
  short r[] = {28, 18, 1, 15, 12, 5, 6, 22, 23, 10, 3, 13, 32, 10, 11, 4};
  short l[] = {14, 15, 3, 13, 29, 20, 3, 7, 15, 24, 9, 8, 4, 19, 6, 5};

  memset(buf, 0x0, sizeof(uint64)*89);

  // This test is really basic, just tests the r/l tables, the s sequence and
  // g function.
  f(buf, dst, 1);
  for(i = 0; i < 16; i++) {
    printf("g(s): %llx, dst[%d]: %llx\n", g(s, r[i], l[i]), i, dst[i]);
    assert(g(s, r[i], l[i]) == dst[i]);
    s = next_s(s);
  }

  memset(buf, 0, sizeof(uint64)*89);
  memset(dst, 0, sizeof(uint64)*16);
  f(buf, dst, 2);
  // Hand check some values to ensure correctness of the tap positions
  // taps: {17, 18, 21, 31, 67}
  assert(dst[0] == g(s, r[0], l[0])); // no taps yet
  s = next_s(s);

  assert(dst[1] == g(s ^ 0xd07aa3807d7a5b97, r[1], l[1]));
  s = next_s(s);

  assert(dst[2] == g(s ^ 0xe6483afd089452a3, r[2], l[2]));
  s = nth_next_s(s, 3);

  assert(dst[5] == g(s ^ 0x38adfa8d142c0363 ^ (0x951cce3d88628c1a & 0xd07aa3807d7a5b97),
	      r[5], l[5]));

  // Test all the taps (also tests back references)
  memset(dst, 0, sizeof(uint64)*16);
  memset(buf, 0x0, sizeof(uint64)*89);
  buf[0]  = 0x1111111100000000;
  buf[72] = 0x1111111111111111;
  buf[71] = 0x1111000000000000;
  buf[68] = 0x1111111100000000;
  buf[58] = 0x1111111111110000;
  buf[22] = 0x1111111111111111;

  f(buf,dst, 1);

  printf("dst[0]: %llx, g_s: %llx\n", dst[0],  g(s_init ^ 0x0000111100001111, r[0], l[0]));
  assert(dst[0] == g(s_init ^ 0x0000111100001111, r[0], l[0]));

  // Test f(buf, dst, 0)
  for(i = 0; i < 89; i++) {
    buf[i] = i;
  }
  f(buf, dst, 0);
  for(i = 0; i < 16; i++) {
    printf("%d: %08x", i, dst[i]);
    assert(dst[i] = 89 - 16 + i);
  }
}

void test_initialize_buf() {
  uint64 buf[89];
  struct md6_config config;
  int i;
  uint8* key_buf;

  for(i = 0; i < 53; i++) {
    config.key[i] = i;
  }
  memset(&(config.key[53]), 0, 11);
  config.keylen = 53;
  config.rounds = 0x0123;
  config.max_level = 31;
  config.digest_size = 512;

  memset(buf, 0x01, sizeof(uint64)*89);
  initialize_buf(buf, &config, 1, 0x4567, 8, 0x0011223344556677);

  // Check that q is present (but not correct)
  for(i = 0; i < 15; i++) {
    assert(buf[i] == q_constant[i]);
  }

  // Check the key bytes are correctly placed
  key_buf = &(buf[15]);
  for(i = 0; i < 53; i++) {
    assert(key_buf[i] == i);
  }
  for(; i < 64; i++) {
    assert(key_buf[i] == 0);
  }

  // Check U and V
  assert(buf[23] = 0x0811223344556677);
  assert(buf[24] = 0x01231f1456735200);

  // Check that the rest is the same as when we initialized it.
  for(i = 25; i < 89; i++) {
    assert(buf[i] == 0x0101010101010101);
  }

  // Check the edge case where keylen = 0
  config.keylen = 0;
  initialize_buf(buf, &config, 1, 0x4567, 8, 0x0011223344556677);
  key_buf = &(buf[15]);
  for(i = 0; i < 64; i++) {
    assert(key_buf[i] == 0);
  }
  assert(buf[24] = 0x01231f1456700200);
}

void test_par() {

  struct md6_config config;
  uint64 message[150];
  uint64 output[16];
  uint64 work_buffer[89];
  uint64 staging_buffer[64];
  int i;

  config.keylen = 48;
  memset(config.key, 0, 48);
  config.key[0] = 0x01;
  config.key[47] = 0x02;
  config.max_level = 31;
  config.digest_size = 512;
  config.rounds = 178;

  memset(message, 0, 150*sizeof(uint64));
  // Add numbers to distinguish each 16 word block
  message[0] = 0x1111111111111111;
  message[16] = 0x2222222222222222;
  message[32] = 0x3333333333333333;
  message[48] = 0x4444444444444444;
  message[64] = 0x5555555555555555;
  message[80] = 0x6666666666666666;
  message[96] = 0x7777777777777777;
  message[112] = 0x8888888888888888;
  message[128] = 0x9999999999999999;
  message[144] = 0xaaaaaaaaaaaaaaaa;
  message[149] = 0xbbbbbbbbbbbbbbb8;

  // Make the message length not a multiple of 64 bits
  par(message, 150*64 - 3, &config, output, 2, 0, 1);
  
  // Run the computations that par runs by "hand"
  // using F and initialize_buffer (which presumably are correct)
  initialize_buf(work_buffer, &config, 0, 0, 1, 0);
  memcpy(&(work_buffer[25]), message, 64*sizeof(uint64));
  f(work_buffer, staging_buffer, config.rounds);
  printf("Theoretical (1, 0): \n");
  print_buf(staging_buffer, 16);

  initialize_buf(work_buffer, &config, 0, 0, 1, 1);
  memcpy(&(work_buffer[25]), &(message[64]), 64*sizeof(uint64));
  f(work_buffer, &(staging_buffer[16]), config.rounds);
  printf("Theoretical (1, 1): \n");
  print_buf(&(staging_buffer[16]), 16);

  initialize_buf(work_buffer, &config, 0, 2691, 1, 2);
  memcpy(&(work_buffer[25]), &(message[128]), 22*sizeof(uint64));
  memset(&(work_buffer[47]), 0, 42*sizeof(uint64));
  f(work_buffer, &(staging_buffer[32]), config.rounds);
  printf("Theoretical (1, 2): \n");
  print_buf(&(staging_buffer[32]), 16);

  memset(&(staging_buffer[48]), 0, 16*sizeof(uint64));
  initialize_buf(work_buffer, &config, 1, 1024, 2, 0);
  memcpy(&(work_buffer[25]), staging_buffer, 64*sizeof(uint64));
  f(work_buffer, staging_buffer, config.rounds);

  for (i = 0; i < 16; i++) {
    printf("par: %llx manual: %llx \n", output[i], staging_buffer[i]);
    assert(output[i] == staging_buffer[i]);
  }
}

void test_seq() {
  struct md6_config config;
  uint64 message[150];
  uint64 output[16];
  uint64 work[89];
  uint64 chain[16];
  int i;

  config.keylen = 48;
  memset(config.key, 0, 48);
  config.rounds = 178;
  config.max_level = 3;
  config.digest_size = 512;

  memset(message, 0, 150*sizeof(uint64));
  // Add numbers to distinguish each 16 word block
  message[0] = 0x1111111111111111;
  message[16] = 0x2222222222222222;
  message[32] = 0x3333333333333333;
  message[48] = 0x4444444444444444;
  message[64] = 0x5555555555555555;
  message[80] = 0x6666666666666666;
  message[96] = 0x7777777777777777;
  message[112] = 0x8888888888888888;
  message[128] = 0x9999999999999999;
  message[144] = 0xaaaaaaaaaaaaaaaa;
  message[149] = 0xbbbbbbbbbbbbbbb8;

  seq(message, 150*64 - 3, &config, output);

  // compute "by hand"
  memset(chain, 0, 16*sizeof(uint64));
  initialize_buf(work, &config, 0, 0, 4, 0);
  memcpy(&(work[25]), chain, 16*sizeof(uint64));
  memcpy(&(work[41]), message, 48*sizeof(uint64));
  f(work, chain, config.rounds);
  printf("Theoretical (4, 0): \n");
  print_buf(chain, 16);

  initialize_buf(work, &config, 0, 0, 4, 1);
  memcpy(&(work[25]), chain, 16*sizeof(uint64));
  memcpy(&(work[41]), &(message[48]), 48*sizeof(uint64));
  f(work, chain, config.rounds);
  printf("Theoretical (4, 1): \n");
  print_buf(chain, 16);

  initialize_buf(work, &config, 0, 0, 4, 2);
  memcpy(&(work[25]), chain, 16*sizeof(uint64));
  memcpy(&(work[41]), &(message[96]), 48*sizeof(uint64));
  f(work, chain, config.rounds);
  printf("Theoretical (4, 2): \n");
  print_buf(chain, 16);

  initialize_buf(work, &config, 1, 2691, 4, 3);
  memcpy(&(work[25]), chain, 16*sizeof(uint64));
  memcpy(&(work[41]), &(message[144]), 6*sizeof(uint64));
  memset(&(work[47]), 0, 42*sizeof(uint64));
  print_buf(work, 89);
  f(work, chain, config.rounds);

  for(i = 0; i < 16; i++) {
    printf("seq: %llx manual: %llx \n", output[i], chain[i]);
    assert(output[i] == chain[i]);
  }
}

void test_md6() {
  struct md6_config config;
  uint64 message[150];
  uint64 mode_output[16];
  uint64 md6_output[16];
  uint64 work[89];
  uint64 intermediate[48];
  int i;

  memset(message, 0, 150*sizeof(uint64));
  // Add numbers to distinguish each 16 word block
  message[0] = 0x1111111111111111;
  message[16] = 0x2222222222222222;
  message[32] = 0x3333333333333333;
  message[48] = 0x4444444444444444;
  message[64] = 0x5555555555555555;
  message[80] = 0x6666666666666666;
  message[96] = 0x7777777777777777;
  message[112] = 0x8888888888888888;
  message[128] = 0x9999999999999999;
  message[144] = 0xaaaaaaaaaaaaaaaa;
  message[149] = 0xbbbbbbbbbbbbbbb8;

  // Test SEQ case
  printf("seq:\n");
  config.keylen = 48;
  memset(config.key, 0, 48);
  config.rounds = 178;
  config.max_level = 0;
  config.digest_size = 508;
  
  md6(message, 150*64 - 3, &config, md6_output);
  seq(message, 150*64 - 3, &config, mode_output);
  mode_output[7] = mode_output[7] & 0xfffffffffffffff0; // test truncation
  assert_buf_equal(md6_output, mode_output, 8);
  
  // Test PAR case
  printf("\npar:\n");
  config.max_level = 3; // only need 2 levels for a message of 150 words
  md6(message, 150*64 - 3, &config, md6_output);
  par(message, 150*64 - 3, &config, mode_output, 2, 0, 1);
  mode_output[7] = mode_output[7] & 0xfffffffffffffff0; // test truncation
  assert_buf_equal(md6_output, mode_output, 8);

  // Test combined case:
  printf("\nmixed mode:\n");
  config.max_level = 1;
  md6(message, 150*64 - 3, &config, md6_output);

  par(message, 64*64, &config, intermediate, 1, 0, 0);
  par(&(message[64]), 64*64, &config, &(intermediate[16]), 1, 1, 0);
  par(&(message[128]), 22*64 - 3, &config, &(intermediate[32]), 1, 2, 0);
  seq(intermediate, 48*64, &config, mode_output);

  mode_output[7] = mode_output[7] & 0xfffffffffffffff0; // test truncation
  assert_buf_equal(md6_output, mode_output, 8);
}

void main() {
  printf("Testing rotate right\n");
  test_rr();
  printf("Testing rotate left\n");
  test_rl();  
  printf("Testing next_s\n");
  test_s();
  printf("Testing g\n");
  test_g();
  printf("Testing f\n");
  test_f();
  printf("Testing initialize buf\n");
  test_initialize_buf();
  printf("Testing par\n");
  test_par();
  printf("Testing seq\n");
  test_seq();
  printf("Testing md6\n");
  test_md6();
  printf("SUCCESS\n"); // All test methods core dump on failure
}
