#ifndef SEAL_DEFINE_H_
#define SEAL_DEFINE_H_

#include <sodium.h>
#include <stddef.h>
#include <stdint.h>

const uint8_t **__seal_magic_location(void);
const size_t *__seal_magic_len_location(void);

#define SEAL_MAGIC (*__seal_magic_location())
#define SEAL_MAGIC_LEN (*__seal_magic_len_location())

#define SEAL_BNONCE_LEN 8
#define SEAL_PNONCE_LEN 4
#define SEAL_NONCE_LEN 12
_Static_assert(SEAL_BNONCE_LEN + SEAL_PNONCE_LEN == SEAL_NONCE_LEN);

#define SEAL_CHUNK_LEN 524288 // 512 kb
#define SEAL_TAG_LEN 16

#define SEAL_KEY_LEN 32
#define SEAL_MEMLIMIT crypto_pwhash_MEMLIMIT_MODERATE
#define SEAL_OPSLIMIT crypto_pwhash_OPSLIMIT_MODERATE
#define SEAL_SALT_LEN 16

#endif
