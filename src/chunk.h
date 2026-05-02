#ifndef SEAL_CHUNK_H_
#define SEAL_CHUNK_H_

#include "cipher.h"
#include <stddef.h>
#include <stdint.h>
#include "define.h"

#define SEAL_CHUNK_MODE_UNDEF 0
#define SEAL_CHUNK_MODE_PLAIN 1
#define SEAL_CHUNK_MODE_CIPHER 2

struct seal_chunk {
	uint8_t pnonce[SEAL_PNONCE_LEN];
	uint8_t buf[SEAL_CHUNK_LEN];
	uint8_t tag[SEAL_TAG_LEN];
	int mode;
	size_t len;
};

int seal_chunk_encrypt(struct seal_chunk *chunk,
		       const struct seal_cipher *cipher);

int seal_chunk_decrypt(struct seal_chunk *chunk,
		       const struct seal_cipher *cipher);

#endif
