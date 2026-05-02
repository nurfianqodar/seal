#include "error.h"
#include "seal.h"
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "define.h"

int main(int argc, const char **argv)
{
	printf("%.*s\n", (int)SEAL_MAGIC_LEN, SEAL_MAGIC);
	printf("%lu\n", SEAL_MAGIC_LEN);
	const char *ipath = "compile_commands.json";
	const char *opath = "compile_commands.json.seal";
	const char *pwd = "secretpassword";
	const size_t pwd_len = strlen(pwd);
	if (SEAL_OK !=
	    seal_encrypt(ipath, opath, (const uint8_t *)pwd, pwd_len, false)) {
		printf("encrypt error: %s\n", seal_error_get_msg());
		return 1;
	}
	if (SEAL_OK !=
	    seal_decrypt(opath, opath, (const uint8_t *)pwd, pwd_len, true)) {
		printf("decrypt error: %s\n", seal_error_get_msg());
		return 1;
	}

	(void)argc;
	(void)argv;
	return 69;
}
