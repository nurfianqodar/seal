#include "seal.h"
#include "chunk.h"
#include "cipher.h"
#include "define.h"
#include "error.h"
#include "file.h"
#include "header.h"
#include "util.h"
#include <linux/limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static seal_error seal_do_encrypt(FILE *ifile, FILE *ofile, const uint8_t *pwd,
				  size_t pwd_len)
{
	seal_error ret = SEAL_OK;
	if (!ifile) {
		seal_error_set_msg("input file cannot null");
		ret = SEAL_E_INVAL;
		goto done;
	}
	if (!ofile) {
		seal_error_set_msg("output file cannot null");
		ret = SEAL_E_INVAL;
		goto done;
	}
	if (!pwd) {
		seal_error_set_msg("password cannot null");
		ret = SEAL_E_INVAL;
		goto done;
	}
	if (pwd_len == 0) {
		seal_error_set_msg("password cannot empty");
		ret = SEAL_E_INVAL;
		goto done;
	}

	struct seal_chunk chunk;
	struct seal_cipher cipher;
	struct seal_header header;
	seal_header_init(&header);
	ret = seal_cipher_init(&cipher, &header, pwd, pwd_len);
	if (ret != SEAL_OK) {
		goto cleanup;
	}
	ret = seal_file_write_exact(ofile, SEAL_MAGIC, SEAL_MAGIC_LEN);
	if (ret != SEAL_OK) {
		goto cleanup;
	}
	ret = seal_file_write_header(ofile, &header);
	if (ret != SEAL_OK) {
		goto cleanup;
	}
	while (true) {
		seal_memzero(&chunk, sizeof chunk);
		ret = seal_file_read_chunk(ifile, &chunk,
					   SEAL_CHUNK_MODE_PLAIN);
		if (ret != SEAL_OK) {
			goto cleanup;
		}
		if (chunk.len == 0) {
			goto cleanup;
		}
		ret = seal_chunk_encrypt(&chunk, &cipher);
		if (ret != SEAL_OK) {
			goto cleanup;
		}
		ret = seal_file_write_chunk(ofile, &chunk);
		if (ret != SEAL_OK) {
			goto cleanup;
		}
	}
	ret = seal_file_flush(ofile);
	if (ret != SEAL_OK) {
		goto cleanup;
	}
cleanup:
	seal_memzero(&chunk, sizeof chunk);
	seal_memzero(&cipher, sizeof cipher);
	seal_memzero(&header, sizeof header);
done:
	return ret;
}

static seal_error seal_do_decrypt(FILE *ifile, FILE *ofile, const uint8_t *pwd,
				  size_t pwd_len)
{
	seal_error ret = SEAL_OK;
	if (!ifile) {
		seal_error_set_msg("input file cannot null");
		ret = SEAL_E_INVAL;
		goto done;
	}
	if (!ofile) {
		seal_error_set_msg("output file cannot null");
		ret = SEAL_E_INVAL;
		goto done;
	}
	if (!pwd) {
		seal_error_set_msg("password cannot null");
		ret = SEAL_E_INVAL;
		goto done;
	}
	if (pwd_len == 0) {
		seal_error_set_msg("password cannot empty");
		ret = SEAL_E_INVAL;
		goto done;
	}
	struct seal_chunk chunk;
	struct seal_cipher cipher;
	struct seal_header header;
	ret = seal_file_read_header(ifile, &header);
	if (ret != SEAL_OK) {
		goto cleanup;
	}

	ret = seal_cipher_init(&cipher, &header, pwd, pwd_len);
	if (ret != SEAL_OK) {
		goto cleanup;
	}

	while (true) {
		seal_memzero(&chunk, sizeof chunk);
		ret = seal_file_read_chunk(ifile, &chunk,
					   SEAL_CHUNK_MODE_CIPHER);
		if (ret != SEAL_OK) {
			goto cleanup;
		}
		if (chunk.len == 0) {
			goto cleanup;
		}
		ret = seal_chunk_decrypt(&chunk, &cipher);
		if (ret != SEAL_OK) {
			goto cleanup;
		}
		ret = seal_file_write_chunk(ofile, &chunk);
		if (ret != SEAL_OK) {
			goto cleanup;
		}
	}
cleanup:
	seal_memzero(&chunk, sizeof chunk);
	seal_memzero(&cipher, sizeof cipher);
	seal_memzero(&header, sizeof header);
done:
	return ret;
}

static seal_error gen_tmp_path(const char *orig, char *tmp)
{
	seal_error ret = SEAL_OK;
	if (!orig) {
		seal_error_set_msg("origin path cannot null");
		ret = SEAL_E_INVAL;
		goto done;
	}
	if (!orig) {
		seal_error_set_msg("tmp path buffer cannot null");
		ret = SEAL_E_INVAL;
		goto done;
	}

	const char *last_slash = strrchr(orig, '/');
	size_t dir_len = 0;

	if (last_slash) {
		dir_len = last_slash - orig;
	} else {
		dir_len = 1;
	}
	char rand_str[32];
	snprintf(rand_str, sizeof(rand_str), "%ld_%d", time(NULL), getpid());
	if (last_slash) {
		snprintf(tmp, PATH_MAX, "%.*s/%s", (int)dir_len, orig,
			 rand_str);
	} else {
		snprintf(tmp, PATH_MAX, "./%s", rand_str);
	}

	if (seal_file_path_is_exists(tmp)) {
		seal_error_set_msg("unable to create temporary file");
		ret = SEAL_E_EXISTS;
		goto done;
	}
done:
	return ret;
}

seal_error seal_encrypt(const char *_ipath, const char *_opath,
			const uint8_t *pwd, size_t pwd_len, bool override)
{
	seal_error ret;
	char ipath[PATH_MAX], opath[PATH_MAX], tmp_opath[PATH_MAX];
	snprintf(ipath, PATH_MAX, "%s", _ipath);
	snprintf(opath, PATH_MAX, "%s", _opath);
	ret = gen_tmp_path(opath, tmp_opath);
	if (ret != SEAL_OK) {
		goto done;
	}
	if (seal_file_path_is_exists(opath) && !override) {
		seal_error_set_msg("output file already exists");
		ret = SEAL_E_EXISTS;
		goto done;
	}
	FILE *ifile, *ofile;
	ret = seal_file_open(&ifile, ipath, SEAL_FILE_MODE_PLAIN);
	if (ret != SEAL_OK) {
		goto done;
	}
	ret = seal_file_create(&ofile, tmp_opath, false);
	if (ret != SEAL_OK) {
		goto close_input;
	}
	ret = seal_do_encrypt(ifile, ofile, pwd, pwd_len);
	if (ret != SEAL_OK) {
		goto cleanup;
	}
	if (0 != rename(tmp_opath, opath)) {
		ret = SEAL_E_MOVE;
		seal_error_set_msg("unable to create output from tmp");
		goto cleanup;
	}
cleanup:
	seal_file_close(&ofile);
	if (ret != SEAL_OK) {
		remove(tmp_opath);
	}
close_input:
	seal_file_close(&ifile);
done:
	return ret;
}

seal_error seal_decrypt(const char *_ipath, const char *_opath,
			const uint8_t *pwd, size_t pwd_len, bool override)
{
	seal_error ret = SEAL_OK;
	char ipath[PATH_MAX], opath[PATH_MAX], tmp_opath[PATH_MAX];
	snprintf(ipath, PATH_MAX, "%s", _ipath);
	snprintf(opath, PATH_MAX, "%s", _opath);
	if (seal_file_path_is_exists(opath) && !override) {
		seal_error_set_msg("output file already exists");
		ret = SEAL_E_EXISTS;
		goto done;
	}
	ret = gen_tmp_path(opath, tmp_opath);
	if (ret != SEAL_OK) {
		goto done;
	}

	FILE *ifile, *ofile;
	ret = seal_file_open(&ifile, ipath, SEAL_FILE_MODE_CIPHER);
	if (ret != SEAL_OK) {
		goto done;
	}
	ret = seal_file_create(&ofile, tmp_opath, false);
	if (ret != SEAL_OK) {
		goto close_input;
	}
	ret = seal_do_decrypt(ifile, ofile, pwd, pwd_len);
	if (ret != SEAL_OK) {
		goto cleanup;
	}

	if (0 != rename(tmp_opath, opath)) {
		ret = SEAL_E_MOVE;
		seal_error_set_msg("unable to create output from tmp");
		goto cleanup;
	}

cleanup:
	seal_file_close(&ofile);
	if (ret != SEAL_OK) {
		remove(tmp_opath);
	}
close_input:
	seal_file_close(&ifile);
done:
	return ret;
}
