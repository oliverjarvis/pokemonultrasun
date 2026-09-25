// Battle.cro: search a u16 table. Placeholder name until identified.

#include "types.h"

extern "C" {

// 0x61EE0: is `value` one of the first `count` entries of `table`?
bool sub_00061EE0(u16 value, const u16* table, u32 count)
{
    for (u32 i = 0; i < count; i++) {
        if (table[i] == value) {
            return true;
        }
    }
    return false;
}

}  // extern "C"
