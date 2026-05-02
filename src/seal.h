#ifndef SEAL_H_
#define SEAL_H_

#include <stddef.h>
#include <stdint.h>

int seal_encrypt(const char *ipath, const char *opath, const uint8_t *pwd,
		 size_t pwd_len, bool override);

int seal_decrypt(const char *ipath, const char *opath, const uint8_t *pwd,
		 size_t pwd_len, bool override);

#endif
