#pragma once
#include <stdio.h>
#include <iostream>

namespace bc
{
#ifdef DEBUG_LOG
#define LOG(X) std::cout << X << std::endl;
#else
#define LOG(X)
#endif
}