#ifndef SEAL_HEADER_H_
#define SEAL_HEADER_H_

#include "define.h"
#include <stdint.h>

struct seal_header {
	uint8_t bnonce[SEAL_BNONCE_LEN];
	uint8_t salt[SEAL_SALT_LEN];
};

void seal_header_init(struct seal_header *out);

#endif
