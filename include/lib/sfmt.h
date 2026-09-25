#ifndef LIB_SFMT_H
#define LIB_SFMT_H

#include "types.h"

#define SFMT_N32 624

struct sfmt_t {
    u32 state[SFMT_N32];
    s32 idx;
};

extern "C" void sfmt_gen_rand_all(sfmt_t* sfmt);

#endif
