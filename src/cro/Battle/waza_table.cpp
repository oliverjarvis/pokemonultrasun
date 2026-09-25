// Battle.cro: membership tests against small move (WazaNo) tables in .rodata.
// The table search itself is in waza_table_search.cpp (not inlined in the original).
// Names are placeholders (sub_<offset>) until the real functions are identified.

#include "types.h"

extern "C" {

extern const u16 rodata_00005674[];
extern const u16 rodata_0000567A[];
extern const u16 rodata_00005686[];

bool sub_00061EE0(u16 value, const u16* table, u32 count);

// 0x602D4
bool sub_000602D4(u16 value)
{
    return sub_00061EE0(value, rodata_00005686, 4);
}

// 0x60F90
bool sub_00060F90(u16 value)
{
    return sub_00061EE0(value, rodata_0000567A, 3);
}

// 0x6106C
bool sub_0006106C(u16 value)
{
    return sub_00061EE0(value, rodata_00005674, 3);
}

}  // extern "C"
