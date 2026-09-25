// FieldRo.cro: accessors returning NodeInheritance<...>::s_Inheritance, imported
// from the static module. Placeholder names (sub_<offset>) until identified;
// these are likely virtual type-query methods of the field node classes.

#include "types.h"

namespace gfl2 {
namespace renderingengine {
namespace scenegraph {

class DagNode;
namespace instance {
class InstanceNode;
}

template <class Derived, class Base>
class NodeInheritance {
public:
    static const u32 s_Inheritance;
};

}  // namespace scenegraph
}  // namespace renderingengine
}  // namespace gfl2

namespace Field {
class FieldNode;
class IField3DObjectNode;
namespace TrialModel {
class FieldTrialModel;
}
}  // namespace Field

using gfl2::renderingengine::scenegraph::NodeInheritance;

extern "C" {

// 0x968C0
const void* sub_000968C0()
{
    return &NodeInheritance<Field::TrialModel::FieldTrialModel, Field::IField3DObjectNode>::s_Inheritance;
}

// 0x968E4
const void* sub_000968E4()
{
    return &NodeInheritance<Field::FieldNode, gfl2::renderingengine::scenegraph::instance::InstanceNode>::s_Inheritance;
}

}  // extern "C"
