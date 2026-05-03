#include "util.h"
#include <sodium.h>
#include <stddef.h>

void seal_memzero(void *ptr, const size_t s)
{
	sodium_memzero(ptr, s);
}

bool seal_memequal(const void *p1, const void *p2, size_t s)
{
	return 0 == sodium_memcmp(p1, p2, s);
}
