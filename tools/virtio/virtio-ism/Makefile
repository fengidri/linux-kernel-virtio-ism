LDFLAGS += -pthread
CFLAGS += -g

virtio-ism-mmap: dev.c main.c server.c
	cc dev.c main.c server.c -o virtio-ism-mmap -l pthread
