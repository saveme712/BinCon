#pragma once

#ifdef VMP
// TODO FIXME
#elif THEMIDA
// TODO FIXME
#else
#define BEGIN_MUTATION(X)
#define END_MUTATION(X)

#define BEGIN_VM(X)
#define END_VM(X)
#define VM(X) BEGIN_VM(__FUNCTION__); X; END_VM(__FUNCTION);
#endif