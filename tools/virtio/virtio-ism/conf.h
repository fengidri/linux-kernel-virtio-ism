#ifndef  __CONF_H__
#define __CONF_H__

#include <sys/mman.h>
#include <stdio.h>
#include <stddef.h>
#include <fcntl.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <poll.h>
#include <linux/virtio_ism.h>
#include <sys/time.h>
#include <pthread.h>
#include <stdarg.h>
#include <sys/types.h>	       /* See NOTES */
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

#define __scalar_type_to_expr_cases(type)				\
		unsigned type:	(unsigned type)0,			\
		signed type:	(signed type)0

#define __unqual_scalar_typeof(x) typeof(				\
		_Generic((x),						\
			 char:	(char)0,				\
			 __scalar_type_to_expr_cases(char),		\
			 __scalar_type_to_expr_cases(short),		\
			 __scalar_type_to_expr_cases(int),		\
			 __scalar_type_to_expr_cases(long),		\
			 __scalar_type_to_expr_cases(long long),	\
			 default: (x)))

#define READ_ONCE(x)	(*(const volatile __unqual_scalar_typeof(x) *)&(x))

#define WRITE_ONCE(x, val)						\
do {									\
	*(volatile typeof(x) *)&(x) = (val);				\
} while (0)

typedef int64_t u64;

struct conf {
	int num;
	int nthread;
	u64 token;
	char *devpath;
	int (*handle)(void);
	int debug;
	char *write_msg;
	bool read_msg;
	int wait_sec;
	int commit;
	bool polling;
	char *ip;
	bool pp;
	int msgsize;
	int tp_chunks;
	int test_case;
};

struct msg {
	u64 token;
};

struct event {
	u64 ev;
	char padding[64];
	u64 done;
	char padding1[64];
};

enum {
	CASE_PP,
	CASE_PP_POLLING,
	CASE_TP,
	CASE_TP_POLLING,
	CASE_TP_POLLING_CHUNKS,
};

#define PAGE_SIZE (4*1024)
#define REGION_SIZE (1024 * 1024)

static inline void llog(const char *fmt, ...)
{
	va_list ap;
	char buf[512];
	int size;

	va_start(ap, fmt);
	size = vsprintf(buf, fmt, ap);
	va_end(ap);

	write(1, buf, size);
}


int server_handle(void);

void commit(int fd);
void *alloc(u64 *token, int *fdp);
void *attach(u64 token, int *_fd);

#endif


