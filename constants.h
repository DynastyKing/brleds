#ifndef MD6_CONSTANTS_H
#define MD6_CONSTANTS_H 1

#define uint64 unsigned long long int
#define uint32 unsigned int
#define uint16 unsigned short int
#define uint8 unsigned char

// debug level. 0 for no output, 1 for some, 2 for lots, etc.
extern int debug; 

// Compression function constants //////////////////////////
/* Shift amounts */
extern short r_shift[];
extern short l_shift[];

/* Tap positions */
extern short tap[];

/* Round constant recurrence info */
extern uint64 s_init;
extern uint64 s_recur;

extern int steps_per_round;

// Mode of operation constants /////////////////////////////////
extern uint64 q_constant[];

extern int q_len; // in words

#endif /* MD6_CONSTANTS_H */
