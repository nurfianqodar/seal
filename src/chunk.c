#include "chunk.h"
#include "cipher.h"
#include "define.h"
#include "error.h"
#include "util.h"
#include <stdint.h>
#include <string.h>

seal_error seal_chunk_encrypt(struct seal_chunk *chunk,
			      const struct seal_cipher *cipher)
{
	if (chunk->mode != SEAL_CHUNK_MODE_PLAIN)
		return seal_error_set_msg("chunk not plaintext"), SEAL_E_INVAL;

	if (chunk->len > SEAL_CHUNK_LEN)
		return seal_error_set_msg("chunk length overflow"),
		       SEAL_E_INVAL;

	seal_error ret;

	uint8_t tmp_cip[SEAL_CHUNK_LEN];
	if ((ret = seal_cipher_encrypt(cipher, chunk->buf, tmp_cip, chunk->len,
				       chunk->tag, chunk->pnonce)) != SEAL_OK)
		return ret;

	memcpy(chunk->buf, tmp_cip, chunk->len);
	seal_memzero(tmp_cip, SEAL_CHUNK_LEN);
	chunk->mode = SEAL_CHUNK_MODE_CIPHER;

	return ret;
}

seal_error seal_chunk_decrypt(struct seal_chunk *chunk,
			      const struct seal_cipher *cipher)
{
	if (chunk->mode != SEAL_CHUNK_MODE_CIPHER)
		return seal_error_set_msg("chunk not ciphertext"), SEAL_E_INVAL;

	if (chunk->len > SEAL_CHUNK_LEN)
		return seal_error_set_msg("chunk length overflow"),
		       SEAL_E_INVAL;

	seal_error ret = SEAL_OK;

	uint8_t tmp_plaintext[SEAL_CHUNK_LEN];
	if ((ret = seal_cipher_decrypt(cipher, chunk->buf, chunk->tag,
				       tmp_plaintext, chunk->len,
				       chunk->pnonce)) != SEAL_OK)
		return ret;

	seal_memzero(chunk->buf, SEAL_CHUNK_LEN);
	seal_memzero(chunk->pnonce, SEAL_PNONCE_LEN);
	seal_memzero(chunk->tag, SEAL_TAG_LEN);
	memcpy(chunk->buf, tmp_plaintext, SEAL_CHUNK_LEN);
	chunk->mode = SEAL_CHUNK_MODE_PLAIN;

	return ret;
}
