#pragma once
#include <stdio.h>
#include <iostream>

namespace bc
{
#define LOGX(X) std::cout << X

#ifdef DEBUG_LOG
#define LOG(X) std::cout << "[" << __FUNCTION__ << "]" << X << std::endl;
#else
#define LOG(X)
#endif

#ifdef DEBUG_TRACE
#define TRACE(X) LOG("[TRACE] " << X)
#else
#define TRACE(X)
#endif

#ifdef DEBUG_INFO
#define INFO(X) LOG("[INFO] " << X)
#else
#define INFO(X)
#endif

#ifdef DEBUG_ERR
#define ERR(X) LOG("[ERR] " << X)
#else
#define ERR(X)
#endif

}