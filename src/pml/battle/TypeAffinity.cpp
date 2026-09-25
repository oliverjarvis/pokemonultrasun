#include "pml/battle/TypeAffinity.h"

namespace pml {
namespace battle {

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
