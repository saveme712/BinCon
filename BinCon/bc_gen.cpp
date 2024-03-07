#include "bc_gen.h"

uint32_t dyn_key_32 = *((uint32_t*)(__TIME__)) ^ *((uint32_t*)(__DATE__));
uint64_t dyn_key_64 = *((uint64_t*)(__TIME__)) ^ *((uint32_t*)(__DATE__));