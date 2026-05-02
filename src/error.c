#include "error.h"
#include <assert.h>
#include <stddef.h>
#include <string.h>

_Thread_local static char last_error[SEAL_ERROR_MSG_MAX_LEN];

void seal_error_set_msg(const char *msg)
{
	if (!msg) {
		last_error[0] = '\0';
		return;
	}
	size_t len = strnlen(msg, SEAL_ERROR_MSG_MAX_LEN - 1);
	memcpy(last_error, msg, len);
	last_error[len] = '\0';
}

const char *seal_error_get_msg(void)
{
	return last_error;
}
