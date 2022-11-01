
#include "conf.h"

extern struct conf conf;

void commit(int fd)
{
	int err;
	err = ioctl(fd, VIRTIO_ISM_IOCTL_KICK);
	if (err) {
		llog("notify fail %d\n", err);
	}
}

void *alloc(u64 *token, int *fdp)
{
	struct virtio_ism_ioctl ctl;
	int fd;
	int err;
	void *shmp;

	fd = open(conf.devpath, O_RDWR);
	if (fd == -1) {
		llog("open fail %d\n", fd);
		return NULL;
	}

	ctl.size = 1024 * 1024;

	err = ioctl(fd, VIRTIO_ISM_IOCTL_ALLOC, &ctl);
	if (err) {
		llog("alloc fail %d\n", err);
		return NULL;
	}

	if (token)
		*token = ctl.token;

	shmp = mmap(NULL, 1024 * 1024, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (MAP_FAILED == shmp) {
		llog("mmap fail %d errnor: %d\n", shmp, errno);
		return NULL;
	}

	if (fdp)
		*fdp = fd;
	else
		close(fd);

	return shmp;
}

void *attach(u64 token, int *_fd)
{
	struct virtio_ism_ioctl ctl;
	int fd;
	int err;
	void *shmp;

	fd = open(conf.devpath, O_RDWR);
	if (fd == -1) {
		llog("open fail %d, err %d\n", fd, errno);
		return NULL;
	}

	ctl.size = 1024 * 1024;
	ctl.token = token;

	err = ioctl(fd, VIRTIO_ISM_IOCTL_ATTACH, &ctl);
	if (err) {
		llog("attach fail %d\n", err);
		return NULL;
	}

	shmp = mmap(NULL, 1024 * 1024, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (MAP_FAILED == shmp) {
		llog("mmap fail %d errnor: %d\n", shmp, errno);
		return NULL;
	}

	if (_fd)
		*_fd = fd;
	else
		close(fd);

	return shmp;
}
