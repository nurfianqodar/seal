#ifndef SEAL_ERROR_H_
#define SEAL_ERROR_H_

#define SEAL_ERROR_MSG_MAX_LEN 512

typedef enum {
	SEAL_OK = 0,
	SEAL_E_INVAL = 1, /* invalid arguments */
	SEAL_E_KEYDRV = 2,
	SEAL_E_ENCRYPT = 3,
	SEAL_E_DECRYPT = 4,
} seal_error;

void seal_error_set_msg(const char *msg);
const char *seal_error_get_msg(void);

#endif
