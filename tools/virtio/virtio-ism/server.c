#include "conf.h"

struct param {
	void *shmp;
	int fd;
	struct conf *conf;
};

static int create_fd(void)
{
	struct sockaddr_in in = {0};
	int err;
	int fd;

	fd = socket(AF_INET, SOCK_STREAM, 0);

	if (fd < 0) {
		printf("create socket error.\n");
		return fd;
	}

	in.sin_family = AF_INET;
	in.sin_addr.s_addr = inet_addr("0.0.0.0");
	in.sin_port = htons(1043);

	err = bind(fd, (struct sockaddr *)&in, sizeof(in));
	if (err) {
		printf("bind server error.\n");
		return err;
	}

	err = listen(fd, 128);
	if (err) {
		printf("listen server error.\n");
		return err;
	}

	return fd;
}

static void * tp_server_polling_chunks(void *shmp, int fd, struct conf *conf)
{
	char *buff, *buf, *chunk;
	struct event *e;
	u64 offset = 0;

	buff = malloc(REGION_SIZE);

	e = (struct event*)shmp;
	buf = shmp + PAGE_SIZE;

	while (true) {
		while (READ_ONCE(e->ev) == offset) continue;

		chunk = buf + (offset % conf->tp_chunks);

		memcpy(buff, chunk, conf->msgsize);
		offset += 1;

		WRITE_ONCE(e->done, offset);
	}
}


static void * tp_server_polling(void *shmp, int fd, struct conf *conf)
{
	struct pollfd pfd;
	char *buff, *buf;
	struct event *e;
	int n, off;

	buff = malloc(REGION_SIZE);

	e = (struct event*) shmp;
	buf = shmp + PAGE_SIZE;

	while (true) {
		while (READ_ONCE(e->ev) == 0) continue;

		memcpy(buff, buf, conf->msgsize);

		WRITE_ONCE(e->ev, 0);
	}
}

static void * tp_server(void *shmp, int fd, struct conf *conf)
{
	struct pollfd pfd;
	char *buf;
	int n;

	pfd.fd = fd;
	pfd.events = POLLIN | POLLOUT;

	buf = malloc(REGION_SIZE);

	while (true) {
		n = poll(&pfd, 1, 99999999);

		memcpy(buf, shmp, conf->msgsize);

		commit(fd);
	}
}

static void * pp_server_polling(void *shmp, int fd, struct conf *conf)
{
	u64 *valp;

	valp = shmp;

	while (true) {
		while (READ_ONCE(*valp) == 0);
		WRITE_ONCE(*valp, 0);
	}

	return 0;
}


static void * pp_server(void *shmp, int fd, struct conf *conf)
{
	struct pollfd pfd;
	u64 *valp;
	int n;

	valp = shmp;

	pfd.fd = fd;
	pfd.events = POLLIN | POLLOUT;

	while (true) {
		n = poll(&pfd, 1, 99999999);

		if (conf->debug)
			llog("* recv val: %lu poll return %d\n", *valp, n);

		WRITE_ONCE(*valp, READ_ONCE(*valp) + 1);

		commit(fd);
	}

	return 0;
}

static void *thread_handler(void *_)
{
	struct param *p = _;
	void *(*h)(void *shmp, int fd, struct conf *conf);

	switch(p->conf->test_case) {
	case CASE_PP:                h = pp_server;                break;
	case CASE_PP_POLLING:        h = pp_server_polling;        break;
	case CASE_TP:                h = tp_server;                break;
	case CASE_TP_POLLING:        h = tp_server_polling;        break;
	case CASE_TP_POLLING_CHUNKS: h = tp_server_polling_chunks; break;
	}

	h(p->shmp, p->fd, p->conf);
}


static int handler(int nfd)
{
	struct conf conf;
	struct msg msg;
	pthread_t th;
	void *shmp;
	int fd;
	int n;
	struct param p;

	setsid();

	n = read(nfd, &conf, sizeof(conf));
	if (n != sizeof(conf)) {
		llog("error recv conf\n");
		close(nfd);
	}

	shmp = alloc(&msg.token, &fd);
	if (!shmp)
		return -1;

	llog("new connection. %d token: %lu\n", nfd, msg.token);

	n = write(nfd, &msg, sizeof(msg));

	p.conf = &conf;
	p.fd = fd;
	p.shmp = shmp;

	pthread_create(&th, 0, thread_handler, (void *)&p);

	char buf[1];

	while (true) {
		n = recv(nfd, buf, 1, 0);
		if (n <= 0) {
			llog("connection %d closed. release token: %lu\n", nfd, msg.token);
			return 0;
		}
	}

	return 0;
}

int server_handle(void)
{
	int fd, nfd, n;
	int pid;

	fd = create_fd();
	if (fd < 0)
		return fd;

	while (true) {
		nfd = accept(fd, NULL, 0);

		pid = fork();

		if (pid == 0) {  // child
			return handler(nfd);
		}

		if (pid == -1) {
			printf("fork err\n");
			return -1;
		}

		close(nfd);
	}
}
