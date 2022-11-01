// SPDX-License-Identifier: GPL-2.0
//
// Usage:
//   vm1: virtio-ism-mmap alloc -> token
//   vm2: virtio-ism-mmap attach <token>
//
//   vm1 will write to shared memory, then notify vm2.
//   After vm2 receive notify, then read from shared memory.
//
//

#include <sys/ioctl.h>
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

typedef int64_t u64;

struct virtio_ism_ioctl {
	u64 size;
	u64 token;
};

#define CMD(rw, nr) _IO##rw(0xAF, nr, struct virtio_ism_ioctl)

#define VIRTIO_ISM_IOCTL_ALLOC	CMD(WR, 0)
#define VIRTIO_ISM_IOCTL_ATTACH	CMD(R,  1)
#define VIRTIO_ISM_IOCTL_NOTIFY	_IO(0xAF, 2)

static void commit(int fd)
{
	int err;
	err = ioctl(fd, VIRTIO_ISM_IOCTL_NOTIFY);
	if (err) {
		printf("notify fail %d\n", err);
	}
}

static void *alloc(int *_fd)
{
	struct virtio_ism_ioctl ctl;
	int fd;
	int err;
	void *shmp;

	fd = open("/dev/virtio-ism", O_RDWR);
	if (fd == -1) {
		printf("open fail %d\n", fd);
		return NULL;
	}

	ctl.size = 1024 * 1024;

	err = ioctl(fd, VIRTIO_ISM_IOCTL_ALLOC, &ctl);
	if (err) {
		printf("alloc fail %d\n", err);
		return NULL;
	}

	printf("token: %lu\n", ctl.token);

	shmp = mmap(NULL, 1024 * 1024, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (MAP_FAILED == shmp) {
		printf("mmap fail %d errnor: %d\n", shmp, errno);
		return NULL;
	}

	*_fd = fd;

	return shmp;
}

static void *attach(u64 token, int *_fd)
{
	struct virtio_ism_ioctl ctl;
	int fd;
	int err;
	void *shmp;

	fd = open("/dev/virtio-ism", O_RDWR);
	if (fd == -1) {
		printf("open fail %d\n", fd);
		return NULL;
	}

	ctl.size = 1024 * 1024;
	ctl.token = token;

	printf("token %lu\n", ctl.token);

	err = ioctl(fd, VIRTIO_ISM_IOCTL_ATTACH, &ctl);
	if (err) {
		printf("attach fail %d\n", err);
		return NULL;
	}

	shmp = mmap(NULL, 1024 * 1024, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (MAP_FAILED == shmp) {
		printf("mmap fail %d errnor: %d\n", shmp, errno);
		return NULL;
	}

	*_fd = fd;

	return shmp;
}

static int alloc_handler()
{
	void *shmp;
	int msgn, l;
	char buf[512];
	int fd;

	shmp = alloc(&fd);
	if (!shmp)
		return -1;

	msgn = 0;
	while (true) {

		sleep(1);

		l = sprintf(buf, "message %d!!", msgn++);
		printf("write: %s\n", buf);

		memcpy(shmp, buf, l);
		commit(fd);
	}
}

static int attach_handler(u64 token)
{
	void *shmp;
	struct pollfd pfd;
	int fd, n;

	shmp = attach(token, &fd);
	if (!shmp)
		return -1;

	pfd.fd = fd;
	pfd.events = POLLIN | POLLOUT;

	while (true) {
		n = poll(&pfd, 1, 99999999);

		printf("== %d =%s\n", n, shmp);
	}
}

int main(int argc, char *argv[])
{
	if (argc == 1)
		return -1;

	if (0 == strcmp(argv[1], "alloc"))
	{
		alloc_handler();
	}

	if (0 == strcmp(argv[1], "attach"))
	{
		if (argc != 3) {
			printf("attach need token");
			return -1;
		}

		attach_handler(atol(argv[2]));
	}

	return 0;
}
