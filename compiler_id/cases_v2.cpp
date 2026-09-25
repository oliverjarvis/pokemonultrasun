// Compiler-identification test cases. Each function reconstructs a small
// function from code.bin (address in the comment); tables are declared extern
// so only code generation is compared.

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef int s32;

// ---------------------------------------------------------------- item
namespace item {

extern const u16 NutsTable[67];       // 0x5BB70E
extern const u16 JewelTable[18];      // 0x5BB86A
extern const u16 MegaStoneTable[47];  // 0x5BB88E
extern const u16 PieceTable[35];      // 0x5BB8EC
extern const u16 BeadsTable[35];      // 0x5BB932

enum BtlPocket {};

u8 ITEM_GetNutsNo(u16 item);

// 0x375CAC
bool ITEM_CheckNuts(u16 item)
{
    return ITEM_GetNutsNo(item) != 0xFF;
}

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

// 0x375F90
u8 GetBattlePocketID(BtlPocket pocket)
{
    const u8 table[] = { 0x10, 0x04, 0x08, 0x01, 0x02, 0xFF, 0x01, 0x00 };
    return table[pocket];
}

}  // namespace item

// ---------------------------------------------------------------- pml
namespace pml {
namespace battle {

class TypeAffinity {
public:
    enum AffinityID {
        TYPEAFF_0,
        TYPEAFF_1_64,
        TYPEAFF_1_32,
        TYPEAFF_1_16,
        TYPEAFF_1_8,
        TYPEAFF_1_4,
        TYPEAFF_1_2,
        TYPEAFF_1,
        TYPEAFF_2,
        TYPEAFF_4,
        TYPEAFF_8,
        TYPEAFF_16,
        TYPEAFF_32,
        TYPEAFF_64,
    };
    enum AboutAffinityID {
        TYPEAFF_ABOUT_NONE,
        TYPEAFF_ABOUT_NORMAL,
        TYPEAFF_ABOUT_ADVANTAGE,
        TYPEAFF_ABOUT_DISADVANTAGE,
    };
    static AffinityID CalcAffinity(u8 atkType, u8 defType1, u8 defType2, bool flag);
    static AboutAffinityID ConvAboutAffinity(AffinityID affinity);
    static AboutAffinityID CalcAffinityAbout(u8 atkType, u8 defType1, u8 defType2, bool flag);
};

// 0x31C3D8
TypeAffinity::AboutAffinityID TypeAffinity::ConvAboutAffinity(AffinityID affinity)
{
    if (affinity > TYPEAFF_1) {
        return TYPEAFF_ABOUT_ADVANTAGE;
    }
    if (affinity == TYPEAFF_1) {
        return TYPEAFF_ABOUT_NORMAL;
    }
    if (affinity == TYPEAFF_0) {
        return TYPEAFF_ABOUT_NONE;
    }
    return TYPEAFF_ABOUT_DISADVANTAGE;
}

// 0x31C3B0
TypeAffinity::AboutAffinityID TypeAffinity::CalcAffinityAbout(u8 atkType, u8 defType1, u8 defType2, bool flag)
{
    return ConvAboutAffinity(CalcAffinity(atkType, defType1, defType2, flag));
}

}  // namespace battle
}  // namespace pml

// ---------------------------------------------------------------- gfl2::math
struct tinymt32_t {
    u32 status[4];
    u32 mat1;
    u32 mat2;
    u32 tmat;
};
extern "C" void tinymt32_init(tinymt32_t* random, u32 seed);  // 0x14A428

struct sfmt_t {
    u32 state[624];
    s32 idx;
};
extern "C" void sfmt_gen_rand_all(sfmt_t* sfmt);  // 0x55EA4C

namespace gfl2 {
namespace math {

class Random {
public:
    struct State {
        u32 status[4];
    };
    void Initialize(u32 seed);
    void Initialize();
    static u32 CreateGeneralSeed();

private:
    tinymt32_t m_tinymt;
};

// 0x3616D0
void Random::Initialize(u32 seed)
{
    m_tinymt.mat1 = 0x8F7011EE;
    m_tinymt.mat2 = 0xFC78FF1F;
    m_tinymt.tmat = 0x3793FDFF;
    tinymt32_init(&m_tinymt, seed);
}

class SFMTRandom {
public:
    u32 Next(u32 max);

private:
    sfmt_t m_sfmt;
};

// 0x360F74
u32 SFMTRandom::Next(u32 max)
{
    sfmt_t* sfmt = &m_sfmt;
    u32* psfmt32 = &sfmt->state[0];
    if (sfmt->idx >= 624) {
        sfmt_gen_rand_all(sfmt);
        sfmt->idx = 0;
    }
    u32 r = psfmt32[sfmt->idx++];
    return r % max;
}

}  // namespace math
}  // namespace gfl2
