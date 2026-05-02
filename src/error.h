#ifndef SEAL_ERROR_H_
#define SEAL_ERROR_H_

#define SEAL_ERROR_MSG_MAX_LEN 512

typedef enum {
	SEAL_OK = 0,
	SEAL_E_INVAL = 1, /* invalid arguments */
	SEAL_E_KEYDRV = 2,
	SEAL_E_ENCRYPT = 3,
	SEAL_E_DECRYPT = 4,
	SEAL_E_OPEN = 5,
	SEAL_E_NOTPLAINFILE = 6,
	SEAL_E_NOTCIPHERFILE = 7,
	SEAL_E_CREATE = 8,
	SEAL_E_READ = 9,
	SEAL_E_WRITE = 10,
	SEAL_E_EOF = 11,
	SEAL_E_CORRUPT = 12,
	SEAL_E_EXISTS = 13,
	SEAL_E_NOENT = 14,
	SEAL_E_MOVE = 15,
} seal_error;

void seal_error_set_msg(const char *msg);
const char *seal_error_get_msg(void);

#endif
