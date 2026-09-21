#pragma once

#include "sbf/lineage.hpp"

// Reconciliation of diverged durable histories lives in lineage.hpp next to the
// lineage tables it operates on. This header exists so that consumers can
// include the reconciler without pulling in the registry service.
