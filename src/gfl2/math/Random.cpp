#include "gfl2/math/Random.h"

namespace gfl2 {
namespace math {

// 0x3616D0. TinyMT32 with the reference default parameters.
void Random::Initialize(u32 seed)
{
    m_tinymt.mat1 = 0x8F7011EE;
    m_tinymt.mat2 = 0xFC78FF1F;
    m_tinymt.tmat = 0x3793FDFF;
    tinymt32_init(&m_tinymt, seed);
}

}  // namespace math
}  // namespace gfl2
