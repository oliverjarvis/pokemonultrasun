#ifndef ITEM_ITEM_H
#define ITEM_ITEM_H

#include "types.h"

namespace item {

enum BtlPocket {};

extern const u16 NutsTable[67];
extern const u16 JewelTable[18];
extern const u16 MegaStoneTable[47];
extern const u16 PieceTable[35];
extern const u16 BeadsTable[35];

bool ITEM_CheckNuts(u16 item);
u8 ITEM_GetNutsNo(u16 item);
bool ITEM_CheckBeads(u16 item);
bool ITEM_CheckJewel(u16 item);
u8 GetBattlePocketID(BtlPocket pocket);

}  // namespace item

#endif
