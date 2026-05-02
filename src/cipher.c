#include "cipher.h"
#include "define.h"
#include "error.h"
#include "header.h"
#include <sodium/crypto_aead_aes256gcm.h>
#include <stddef.h>
#include <stdint.h>
#include <sodium.h>
#include <stdio.h>
#include <string.h>

static void derive_nonce(uint8_t *out, const uint8_t *bnonce,
			 const uint8_t *pnonce)
{
	memcpy(out, bnonce, SEAL_BNONCE_LEN);
	memcpy(out + SEAL_BNONCE_LEN, pnonce, SEAL_PNONCE_LEN);
}

int seal_cipher_init(struct seal_cipher *cipher, struct seal_header *header,
		     const uint8_t *pwd, size_t pwd_len)
{
	if (0 != crypto_pwhash(cipher->key, SEAL_KEY_LEN, (const char *)pwd,
			       pwd_len, header->salt, SEAL_OPSLIMIT,
			       SEAL_MEMLIMIT, SEAL_KEYDRV_ALG)) {
		seal_error_set_msg("key derivation error");
		return SEAL_E_KEYDRV;
	}
	memcpy(cipher->bnonce, header->bnonce, SEAL_BNONCE_LEN);
	return SEAL_OK;
}

int seal_cipher_encrypt(const struct seal_cipher *cipher, const uint8_t *in,
			uint8_t *out, const size_t len, uint8_t *tag_out,
			const uint8_t *pnonce)
{
	if (!cipher) {
		seal_error_set_msg("cipher cannot null");
		return SEAL_E_INVAL;
	}
	if (!in) {
		seal_error_set_msg("plaintext cannot null");
		return SEAL_E_INVAL;
	}
	if (!out) {
		seal_error_set_msg("ciphertext buffer cannot null");
		return SEAL_E_INVAL;
	}
	if (!tag_out) {
		seal_error_set_msg("tag buffer cannot null");
		return SEAL_E_INVAL;
	}
	if (!pnonce) {
		seal_error_set_msg("postfix nonce cannot null");
		return SEAL_E_INVAL;
	}

	uint8_t nonce[SEAL_NONCE_LEN];
	derive_nonce(nonce, cipher->bnonce, pnonce);

	if (0 != crypto_aead_aes256gcm_encrypt_detached(
			 out, tag_out, NULL, in, len, pnonce, SEAL_PNONCE_LEN,
			 NULL, nonce, cipher->key)) {
		seal_error_set_msg("encrypt failed");
		return SEAL_E_ENCRYPT;
	}
	return SEAL_OK;
}

int seal_cipher_decrypt(const struct seal_cipher *cipher, const uint8_t *in,
			const uint8_t *tag, uint8_t *out, const size_t len,
			const uint8_t *pnonce)
{
	if (!cipher) {
		seal_error_set_msg("cipher cannot null");
		return SEAL_E_INVAL;
	}
	if (!in) {
		seal_error_set_msg("ciphertext cannot null");
		return SEAL_E_INVAL;
	}
	if (!tag) {
		seal_error_set_msg("tag cannot null");
		return SEAL_E_INVAL;
	}
	if (!out) {
		seal_error_set_msg("plaintext buffer cannot null");
		return SEAL_E_INVAL;
	}
	if (!pnonce) {
		seal_error_set_msg("postfix nonce cannot null");
		return SEAL_E_INVAL;
	}

	uint8_t nonce[SEAL_NONCE_LEN];
	derive_nonce(nonce, cipher->bnonce, pnonce);

	int ret_sodium;
	if (0 != (ret_sodium = crypto_aead_aes256gcm_decrypt_detached(
			  out, NULL, in, len, tag, pnonce, SEAL_PNONCE_LEN,
			  nonce, cipher->key))) {
		seal_error_set_msg("decrypt failed");
		return SEAL_E_DECRYPT;
	}
	return SEAL_OK;
}
