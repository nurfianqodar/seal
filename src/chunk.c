#include "chunk.h"
#include "cipher.h"
#include "define.h"
#include "error.h"
#include "util.h"
#include <stdint.h>
#include <string.h>

int seal_chunk_encrypt(struct seal_chunk *chunk,
		       const struct seal_cipher *cipher)
{
	if (chunk->mode != SEAL_CHUNK_MODE_PLAIN) {
		seal_error_set_msg(
			"chunk must be in plaintext mode to encrypt");
		return SEAL_E_INVAL;
	}
	if (chunk->len > SEAL_CHUNK_LEN) {
		seal_error_set_msg("chunk length overflow");
		return SEAL_E_INVAL;
	}
	int ret;
	uint8_t tmp_ciphertext[SEAL_CHUNK_LEN];
	ret = seal_cipher_encrypt(cipher, chunk->buf, tmp_ciphertext,
				  chunk->len, chunk->tag, chunk->pnonce);
	if (ret != 0) {
		return ret;
	}
	memcpy(chunk->buf, tmp_ciphertext, chunk->len);
	seal_memzero(tmp_ciphertext, SEAL_CHUNK_LEN);
	chunk->mode = SEAL_CHUNK_MODE_CIPHER;
	return SEAL_OK;
}

int seal_chunk_decrypt(struct seal_chunk *chunk,
		       const struct seal_cipher *cipher)
{
	if (chunk->mode != SEAL_CHUNK_MODE_CIPHER) {
		seal_error_set_msg(
			"chunk must be in ciphertext mode to decrypt");
		return SEAL_E_INVAL;
	}
	if (chunk->len > SEAL_CHUNK_LEN) {
		seal_error_set_msg("chunk length overflow");
		return SEAL_E_INVAL;
	}

	int ret;
	uint8_t tmp_plaintext[SEAL_CHUNK_LEN];
	ret = seal_cipher_decrypt(cipher, chunk->buf, chunk->tag, tmp_plaintext,
				  chunk->len, chunk->pnonce);
	if (ret != 0) {
		return ret;
	}
	seal_memzero(chunk->buf, SEAL_CHUNK_LEN);
	seal_memzero(chunk->pnonce, SEAL_PNONCE_LEN);
	seal_memzero(chunk->tag, SEAL_TAG_LEN);
	memcpy(chunk->buf, tmp_plaintext, SEAL_CHUNK_LEN);
	chunk->mode = SEAL_CHUNK_MODE_PLAIN;
	return SEAL_OK;
}
