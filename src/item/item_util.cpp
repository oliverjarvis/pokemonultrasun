#include "item/item.h"

namespace item {

#ifdef NONMATCHING
// 0x375CAC. The original keeps the `!= 0xFF` test after inlining
// ITEM_GetNutsNo; this version folds it away.
bool ITEM_CheckNuts(u16 item)
{
    return ITEM_GetNutsNo(item) != 0xFF;
}
#endif

// 0x375D90
u8 ITEM_GetNutsNo(u16 item)
{
    for (u32 i = 0; i < 67; i++) {
        if (NutsTable[i] == item) {
            return i;
        }
    }
    return 0xFF;
}

// 0x375EB8
bool ITEM_CheckBeads(u16 item)
{
    for (u32 i = 0; i < 35; i++) {
        if (BeadsTable[i] == item) {
            return true;
        }
    }
    return false;
}

// 0x375F04
bool ITEM_CheckJewel(u16 item)
{
    for (u32 i = 0; i < 18; i++) {
        if (JewelTable[i] == item) {
            return true;
        }
    }
    return false;
}

#ifdef NONMATCHING
// 0x375F90. The original loads the table initializer from .rodata
// (0x5BB6D4); armcc places this one in the code section.
u8 GetBattlePocketID(BtlPocket pocket)
{
    const u8 table[] = { 0x10, 0x04, 0x08, 0x01, 0x02, 0xFF, 0x01, 0x00 };
    return table[pocket];
}
#endif

}  // namespace item
