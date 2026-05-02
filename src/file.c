#include "file.h"
#include "error.h"
#include "util.h"
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include "define.h"
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

int seal_file_open(FILE **f_ptr, const char *path, int mode)
{
	if (mode != SEAL_FILE_MODE_PLAIN || mode != SEAL_FILE_MODE_CIPHER) {
		seal_error_set_msg("invalid open mode");
		return SEAL_E_INVAL;
	}

	*f_ptr = NULL;
	FILE *file = fopen(path, "rb");
	if (!file) {
		seal_error_set_msg(strerror(errno));
		return SEAL_E_OPEN;
	}

	uint8_t magic_buf[SEAL_MAGIC_LEN];
	seal_memzero(magic_buf, SEAL_MAGIC_LEN);

	size_t readn = 0;
	size_t n;
	while (readn < SEAL_MAGIC_LEN) {
		n = fread(magic_buf + readn, 1, SEAL_MAGIC_LEN - readn, file);
		if (0 == n) {
			if (feof(file)) {
				break;
			}
			if (ferror(file)) {
				seal_error_set_msg(strerror(errno));
				fclose(file);
				return SEAL_E_OPEN;
			}
		}
		readn += n;
	}
	bool is_valid_magic = seal_eql(SEAL_MAGIC, magic_buf, SEAL_MAGIC_LEN);
	if (is_valid_magic && mode == SEAL_FILE_MODE_CIPHER) {
		*f_ptr = file;
		return SEAL_OK;
	}
	if (is_valid_magic && mode == SEAL_FILE_MODE_PLAIN) {
		seal_error_set_msg("file was encrypted");
		fclose(file);
		return SEAL_E_NOTPLAINFILE;
	}

	// reset cursor in plain mode
	if (0 != fseek(file, 0, SEEK_SET)) {
		seal_error_set_msg(strerror(errno));
		fclose(file);
		return SEAL_E_OPEN;
	}
	*f_ptr = file;
	return SEAL_OK;
}

int seal_file_create(FILE **f_ptr, const char *path, bool override)
{
	int oflag = O_CREAT | O_CLOEXEC | O_WRONLY;
	if (override) {
		oflag |= O_TRUNC;
	} else {
		oflag |= O_EXCL;
	}
	int fd = open(path, oflag, 0644);
	if (-1 == fd) {
		seal_error_set_msg(strerror(errno));
		return SEAL_E_CREATE;
	}
	FILE *file = fdopen(fd, "wb");
	if (!file) {
		seal_error_set_msg(strerror(errno));
		close(fd);
		return SEAL_E_CREATE;
	}
	*f_ptr = file;
	return SEAL_OK;
}

void seal_file_close(FILE **f_ptr)
{
	if (!f_ptr) {
		return;
	}
	if (!*f_ptr) {
		return;
	}
	fclose(*f_ptr);
}
