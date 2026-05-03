#ifndef SEAL_H_
#define SEAL_H_

#include "error.h"
#include <stddef.h>
#include <stdint.h>

seal_error seal_encrypt(const char *ipath, const char *opath,
			const uint8_t *pwd, size_t pwd_len, bool override);

seal_error seal_decrypt(const char *ipath, const char *opath,
			const uint8_t *pwd, size_t pwd_len, bool override);

#endif
