#ifndef SEAL_ERROR_H_
#define SEAL_ERROR_H_

#define SEAL_ERROR_MSG_MAX_LEN 512

typedef enum {
	SEAL_OK = 0,
	SEAL_E_INVAL = 1, /* invalid arguments */
} seal_error;

void seal_error_set_msg(const char *msg);
const char *seal_error_get_msg(void);

#endif
