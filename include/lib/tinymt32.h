#ifndef LIB_TINYMT32_H
#define LIB_TINYMT32_H

#include "types.h"

struct tinymt32_t {
    u32 status[4];
    u32 mat1;
    u32 mat2;
    u32 tmat;
};

extern "C" void tinymt32_init(tinymt32_t* random, u32 seed);

#endif
