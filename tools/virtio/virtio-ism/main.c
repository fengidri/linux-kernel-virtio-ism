// SPDX-License-Identifier: GPL-2.0
//

#include "conf.h"

struct conf conf;

#define time_us(start, end) \
	((end.tv_sec - start.tv_sec) * 1000 * 1000 + end.tv_usec - start.tv_usec)

static int trigger_server(struct msg *msg)
{
	struct sockaddr_in in = {0};
	int fd;
	int err;

	in.sin_family = AF_INET;
	in.sin_addr.s_addr = inet_addr(conf.ip);
	in.sin_port = htons(1043);

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		printf("create socket error.\n");
		return fd;
	}

	err = connect(fd, (struct sockaddr *)&in, sizeof(in));
	if (err) {
		printf("connect error.\n");
		return err;
	}

	err = send(fd, &conf, sizeof(conf), 0);
	if (err != sizeof(conf)) {
		printf("send conf error.\n");
		return err;
	}

	err = recv(fd, msg, sizeof(*msg), 0);
	if (err != sizeof(*msg)) {
		printf("recv msg error.\n");
		return err;
	}

	printf("recv token: %lu\n", msg->token);

	return 0;
}


static int test_case_alloc_one_thread(void)
{
	struct timeval start, end;
	u64 n = conf.num;
	int i, us;
	void *p;

	gettimeofday(&start, NULL);

	for (i = 0; i < conf.num; ++i)
	{
		p = alloc(NULL, NULL);
		if (!p) {
			llog("alloc fail\n");
			exit(-1);
		}

		if (conf.debug)
			llog("alloc done: %d\n", i);
	}

	gettimeofday(&end, NULL);

	us = time_us(start, end);

	llog("time: %dus alloc num: %d latency: %dus\n", us, i, us / i);

	return 0;
}

static int test_case_alloc_handler(void)
{
	struct pollfd pfd;
	u64 token;
	char *p;
	int n, fd;

	p = alloc(&token, &fd);

	if (!p) {
		llog("alloc fail\n");
		return -1;
	}


	llog("token: %lu\n", token);

	if (conf.write_msg)
		memcpy(p, conf.write_msg, strlen(conf.write_msg));

	pfd.fd = fd;
	pfd.events = POLLIN | POLLOUT;

	while (true) {
		n = poll(&pfd, 1, 99999999);

		llog("recv notify callback.\n");
		llog("message: [%s]\n", p);
	}
}

static int test_case_attach_handler(void)
{
	u64 token;
	void *p;
	int fd;

	if (!conf.token) {
		llog("need token by -t\n");
		return 0;
	}

	p = attach(conf.token, &fd);

	if (!p) {
		llog("attach fail\n");
		return -1;
	}

	if (conf.read_msg)
		llog("message: [%s]\n", p);

	if (conf.write_msg)
		memcpy(p, conf.write_msg, strlen(conf.write_msg));

	if (conf.commit)
		commit(fd);
}

static void * test_case_alloc_multi_thread_handler(void *_)
{
	test_case_alloc_one_thread();
	return NULL;
}

static int test_case_alloc_multi_thread(void)
{
	struct timeval start, end;
	pthread_t *th;
	u64 n = conf.num;
	u64 nthread = conf.nthread;
	int i;

	th = malloc(n * sizeof(*th));

	gettimeofday(&start, NULL);

	for (i = 0; i < nthread; ++i)
		pthread_create(th + i, 0,
			       test_case_alloc_multi_thread_handler, NULL);

	gettimeofday(&end, NULL);

	llog("time: %dus alloc num: %dus\n", time_us(start, end), n);

	return 0;
}

static u64 tp_client_polling_multi_chunks(void *shmp, int fd)
{
	void *buf, *chunk;
	u64 traffic = 0;
	struct event *e;
	u64 offset = 0;
	int n;

	n = conf.num;

	e = (struct event*)shmp;
	buf = shmp + PAGE_SIZE;

	n = n * conf.tp_chunks;
	while (n > 0) {

		while (true) {
			if (READ_ONCE(e->ev) - READ_ONCE(e->done) >= conf.tp_chunks)
				continue;

			break;
		}

		chunk = buf + (offset % conf.tp_chunks);

		memset(chunk, (char)n, conf.msgsize);
		traffic += conf.msgsize;

		offset += 1;

		WRITE_ONCE(e->ev, offset);

		--n;
	}

	return traffic;
}

static u64 tp_client_polling(void *shmp, int fd)
{
	u64 traffic = 0;
	struct event *e;
	void *buf;
	int n;

	n = conf.num;

	e = (struct event*) shmp;
	buf = shmp + PAGE_SIZE;

	while (n > 0) {

		memset(buf, (char)n, conf.msgsize);
		traffic += conf.msgsize;

		WRITE_ONCE(e->ev, 1);

		while (READ_ONCE(e->ev) == 1) continue;

		--n;
	}

	return traffic;
}

static u64 tp_client(void *shmp, int fd)
{
	u64 token, traffic = 0;
	struct pollfd pfd;
	int n;

	n = conf.num;

	pfd.fd = fd;
	pfd.events = POLLIN | POLLOUT;

	while (n--) {
		memset(shmp, (char)n, conf.msgsize);
		traffic += conf.msgsize;

		commit(fd);

		poll(&pfd, 1, 99999999);
	}

	return traffic;
}

static int memset_handle(void)
{
	struct timeval start, end;
	int n = conf.num;
	char buf[REGION_SIZE];
	u64 traffic = 0;

	gettimeofday(&start, NULL);
	while (--n) {
		memset(buf, (char)1, sizeof(buf));
		traffic += sizeof(buf);

	}
	gettimeofday(&end, NULL);

	int us = time_us(start, end);

	llog("time: %dus msg num: %d tp: %d GBps\n", us, conf.num,
	     traffic * 1000 * 1000 / us  / 1024 / 1024 / 1024);
	return 0;
}

static u64 pp_client_polling(void *shmp, int fd)
{
	int n;
	u64 *valp;

	n = conf.num;

	valp = shmp;

	while (n--) {
		WRITE_ONCE(*valp, 1);
		while (READ_ONCE(*valp) == 1);
	}

	return 0;
}

static u64 pp_client(void *shmp, int fd)
{
	struct pollfd pfd;
	int n;
	u64 *valp, o;

	n = conf.num;

	valp = shmp;

	pfd.fd = fd;
	pfd.events = POLLIN | POLLOUT;

	while (n--) {
		o = READ_ONCE(*valp);

		commit(fd);

		if (conf.debug)
			llog("commit val: origin %lu %lu\n", o, READ_ONCE(*valp));

		poll(&pfd, 1, 99999999);

		if (READ_ONCE(*valp) != o + 1) {
			llog("pp-client recv error val %d\n", READ_ONCE(*valp));
			exit(-1);
		}
	}

	return 0;
}

static int tp_pp_handler()
{
	struct timeval start, end;
	void *shmp;
	u64 token, traffic, trafficps;
	int fd;
	struct msg msg;
	u64 (*h)(void *shmpm, int fd);
	int err;

	err = trigger_server(&msg);
	if (err)
		return err;

	token = msg.token;

	shmp = attach(token, &fd);
	if (!shmp)
		return -1;

	if (conf.msgsize > REGION_SIZE - PAGE_SIZE)
		conf.msgsize = REGION_SIZE - PAGE_SIZE;

	if (conf.msgsize * conf.tp_chunks > REGION_SIZE - PAGE_SIZE) {
		llog("conf.msgsize * conf.tp_chunks too big\n");
		return -1;
	}

	switch(conf.test_case) {
	case CASE_PP:                h = pp_client;                      break;
	case CASE_PP_POLLING:        h = pp_client_polling;              break;
	case CASE_TP:                h = tp_client;                      break;
	case CASE_TP_POLLING:        h = tp_client_polling;              break;
	case CASE_TP_POLLING_CHUNKS: h = tp_client_polling_multi_chunks; break;
	}

	gettimeofday(&start, NULL);
	traffic = h(shmp, fd);
	gettimeofday(&end, NULL);

	int us = time_us(start, end);

	trafficps = traffic * 1000 * 1000 / us / 1024 / 1024;

	llog("Time:       %d us\n"
	     "Msg Num:    %d\n"
	     "Traffic:    %lld Bytes\n"
	     "Throughput: %d.%03d GBps\n"
	     "Latency:    %d us\n",
	     us, conf.num, traffic,
	     trafficps / 1024, trafficps % 1024, us / conf.num);
}

static int tp_client_handle(void)
{
	if (conf.polling) {
		if (conf.tp_chunks)
			conf.test_case = CASE_TP_POLLING_CHUNKS;
		else
			conf.test_case = CASE_TP_POLLING;
	} else {
		conf.test_case = CASE_TP;
	}

	tp_pp_handler();
}

static int pp_client_handle(void)
{
	if (conf.polling)
		conf.test_case = CASE_PP_POLLING;
	else
		conf.test_case = CASE_PP;

	tp_pp_handler();
}

static int get_stats(void)
{
	struct virtio_ism_stat stats;
	int fd;
	int err;
	void *shmp;

	fd = open(conf.devpath, O_RDWR);
	if (fd == -1) {
		llog("open fail %d\n", fd);
		return -1;
	}

	err = ioctl(fd, VIRTIO_ISM_IOCTL_STAT, &stats);
	if (err) {
		llog("stats fail %d\n", err);
		return -1;
	}

	llog("total size:    %llu\n", stats.total_size);
	llog("region size:   %llu\n", stats.chunk_size);
	llog("region active: %llu\n", stats.region_active);
	llog("region free:   %llu\n", stats.region_free);

	llog("alloc:         %llu\n", stats.alloc);
	llog("attach:        %llu\n", stats.attach);
	llog("detach:        %llu\n", stats.detach);
	llog("kick:          %llu\n", stats.kick);

	llog("cmd err:       %llu\n", stats.cmd_err);
	llog("cmd success:   %llu\n", stats.cmd_success);

	llog("irq inuse:     %llu\n", stats.irq_inuse);

	return 0;
}

int main(int argc, char *argv[])
{
	int i;
	char *opt, *val;

	conf.num = 10000;
	conf.devpath = "/dev/vism0";
	conf.nthread = 1;
	conf.msgsize = REGION_SIZE;

	for (i = 1; i < argc; ++i) {
		opt = argv[i];

		if (0 == strcmp(opt, "stats"))
		{
			conf.handle = get_stats;
			continue;
		}

		if (0 == strcmp(opt, "server")) {
			conf.handle = server_handle;
			continue;
		}

		if (0 == strcmp(opt, "memset"))
		{
			conf.handle = memset_handle;
			continue;
		}

		if (0 == strcmp(opt, "tp"))
		{
			conf.handle = tp_client_handle;
			continue;
		}

		if (0 == strcmp(opt, "pp"))
		{
			conf.handle = pp_client_handle;
			continue;
		}

		if (0 == strcmp(opt, "alloc"))
		{
			conf.handle = test_case_alloc_handler;
			continue;
		}

		if (0 == strcmp(opt, "attach"))
		{
			conf.handle = test_case_attach_handler;
			continue;
		}

		if (0 == strcmp(opt, "alloc-one-thread"))
		{
			conf.handle = test_case_alloc_one_thread;
			continue;
		}

		if (0 == strcmp(opt, "alloc-multi-thread"))
		{
			conf.handle = test_case_alloc_multi_thread;
			continue;
		}

		if (0 == strcmp(opt, "--debug")) {
			conf.debug = 1;
			continue;
		}

		if (0 == strcmp(opt, "--read-msg")) {
			conf.read_msg = 1;
			continue;
		}

		if (0 == strcmp(opt, "--commit")) {
			conf.commit = 1;
			continue;
		}

		if (0 == strcmp(opt, "--polling")) {
			conf.polling = 1;
			continue;
		}

		if (i == argc) {
			llog("%s need opt\n", opt);
			return -1;
		}

		val = argv[++i];

		if (0 == strcmp(opt, "-i")) {
			conf.ip = val;
			continue;
		}

		if (0 == strcmp(opt, "-d")) {
			conf.devpath = val;
			continue;
		}

		if (0 == strcmp(opt, "-n")) {
			conf.num = atol(val);
			continue;
		}

		if (0 == strcmp(opt, "-t")) {
			conf.token = atol(val);
			llog("token: %lu\n", conf.token);
			continue;
		}

		if (0 == strcmp(opt, "--write-msg")) {
			conf.write_msg = val;
			continue;
		}

		if (0 == strcmp(opt, "--wait")) {
			conf.wait_sec = atoi(val);
			continue;
		}

		if (0 == strcmp(opt, "--nthread")) {
			conf.nthread = atol(val);
			continue;
		}

		if (0 == strcmp(opt, "--tp-chunks")) {
			conf.tp_chunks = atol(val);
			continue;
		}

		if (0 == strcmp(opt, "--msg-size")) {
			int l;

			conf.msgsize = atol(val);

			l = strlen(val);
			if (val[l - 1] == 'k' || val[l - 1] == 'K')
				conf.msgsize = conf.msgsize * 1024;

			if (conf.msgsize > REGION_SIZE) {
				printf("too big msg-size.\n");
				return -1;
			}

			continue;
		}

		printf("invalid opt. %s\n", opt);
		return -1;
	}

	if (conf.handle)
		conf.handle();

	if (conf.wait_sec)
		sleep(conf.wait_sec);

	return 0;
}
