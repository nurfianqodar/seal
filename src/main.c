#include "error.h"
#include "seal.h"
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

int main(int argc, const char **argv)
{
	(void)argc;
	(void)argv;

	const char *ipath = "compile_commands.json";
	const char *opath = "compile_commands.json.seal";
	const char *pwd = "secretpassword";

	const size_t pwd_len = strlen(pwd);

	if (SEAL_OK !=
	    seal_encrypt(ipath, opath, (const uint8_t *)pwd, pwd_len, false)) {
		return 1;
	}

	if (SEAL_OK !=
	    seal_decrypt(opath, opath, (const uint8_t *)pwd, pwd_len, true)) {
		return 1;
	}

	return 69;
}
