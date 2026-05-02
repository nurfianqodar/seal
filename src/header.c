#include "header.h"
#include "define.h"
#include <sodium.h>

void seal_header_init(struct seal_header *out)
{
	randombytes_buf(out->bnonce, SEAL_BNONCE_LEN);
	randombytes_buf(out->salt, SEAL_SALT_LEN);
}
