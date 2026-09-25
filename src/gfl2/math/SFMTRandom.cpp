#include "gfl2/math/SFMTRandom.h"

namespace gfl2 {
namespace math {

// 0x360F74. Reference sfmt_genrand_uint32, reduced modulo max.
u32 SFMTRandom::Next(u32 max)
{
    sfmt_t* sfmt = &m_sfmt;
    u32* psfmt32 = &sfmt->state[0];
    if (sfmt->idx >= SFMT_N32) {
        sfmt_gen_rand_all(sfmt);
        sfmt->idx = 0;
    }
    u32 r = psfmt32[sfmt->idx++];
    return r % max;
}

}  // namespace math
}  // namespace gfl2
