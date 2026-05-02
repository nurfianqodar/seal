#include "util.h"
#include <sodium.h>
#include <stddef.h>

void seal_memzero(void *ptr, const size_t s)
{
	sodium_memzero(ptr, s);
}
