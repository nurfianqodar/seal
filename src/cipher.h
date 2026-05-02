#ifndef SEAL_CIPHER_H_
#define SEAL_CIPHER_H_

#include "header.h"
#include <stddef.h>
#include <stdint.h>
#include "define.h"

struct seal_cipher {
	uint8_t bnonce[SEAL_BNONCE_LEN];
	uint8_t key[SEAL_KEY_LEN];
};

int seal_cipher_init(struct seal_cipher *cipher, struct seal_header *header,
		     const uint8_t *pwd, size_t pwd_len);

int seal_cipher_encrypt(const struct seal_cipher *cipher, const uint8_t *in,
			uint8_t *out, const size_t len, uint8_t *tag_out,
			const uint8_t *pnonce);

int seal_cipher_decrypt(const struct seal_cipher *cipher, const uint8_t *in,
			const uint8_t *tag, uint8_t *out, const size_t len,
			const uint8_t *pnonce);

#endif
