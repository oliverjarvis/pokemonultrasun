#ifndef PML_BATTLE_TYPEAFFINITY_H
#define PML_BATTLE_TYPEAFFINITY_H

#include "types.h"

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

}  // namespace battle
}  // namespace pml

#endif
