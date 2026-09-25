#ifndef GFL2_MATH_RANDOM_H
#define GFL2_MATH_RANDOM_H

#include "types.h"
#include "lib/tinymt32.h"

namespace gfl2 {
namespace math {

// TinyMT32 wrapper. Incomplete: only members needed by matched code so far.
class Random {
public:
    struct State {
        u32 status[4];
    };

    void Initialize(u32 seed);
    void Initialize();
    void Initialize(State state);
    static u32 CreateGeneralSeed();

private:
    tinymt32_t m_tinymt;
};

}  // namespace math
}  // namespace gfl2

#endif
