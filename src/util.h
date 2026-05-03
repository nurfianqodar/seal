#ifndef SEAL_UTIL_H_
#define SEAL_UTIL_H_

#include <stddef.h>

void seal_memzero(void *ptr, const size_t s);
bool seal_memequal(const void *p1, const void *p2, const size_t s);
bool seal_eql(const void *p1, const void *p2, size_t s);

#endif
