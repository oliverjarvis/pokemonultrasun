#ifndef GFL2_MATH_SFMTRANDOM_H
#define GFL2_MATH_SFMTRANDOM_H

#include "types.h"
#include "lib/sfmt.h"

namespace gfl2 {
namespace math {

// SFMT19937 wrapper. Incomplete: only members needed by matched code so far.
class SFMTRandom {
public:
    u32 Next(u32 max);

private:
    sfmt_t m_sfmt;
};

}  // namespace math
}  // namespace gfl2

#endif
