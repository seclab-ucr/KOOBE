#ifndef S2E_PLUGINS_SERIALIZATION_H
#define S2E_PLUGINS_SERIALIZATION_H

#include <klee/Expr.h>
#include <klee/util/ExprTemplates.h>
#include <klee/util/Ref.h>
#include <s2e/S2E.h>

#include "Evaluation.h"

namespace s2e {
namespace plugins {

void serialize_init();
void deserialize_init();

void serialize(std::ofstream &ofs, Capability &cap);
bool deserialize(std::ifstream &ifs, Capability &cap);

void serialize(std::ofstream &ofs, klee::ConstraintManager &manager);
bool deserialize(std::ifstream &ifs, klee::ConstraintManager &manager);

void serialize(std::ofstream &ofs, const klee::ref<klee::Expr> &expr);
bool deserialize(std::ifstream &ifs, klee::ref<klee::Expr> &expr);

void serialize(std::ofstream &ofs, CapSummary &caps,
               std::map<uint64_t, Spot> &spots);
bool deserialize(std::ifstream &ifs, CapSummary &caps,
                 std::map<uint64_t, Spot> &spots);

}
}

#endif
