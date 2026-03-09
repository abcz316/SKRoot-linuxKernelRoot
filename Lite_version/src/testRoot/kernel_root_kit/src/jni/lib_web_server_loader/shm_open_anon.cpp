// Copyright 2019 Lassi Kortela
// SPDX-License-Identifier: ISC
#include "shm_open_anon.h"
#ifdef __linux__
//#define _GNU_SOURCE
#include <linux/memfd.h>
#include <linux/unistd.h>
#endif
#include <sys/types.h>

#include <sys/mman.h>

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#undef IMPL_MEMFD
#undef IMPL_POSIX
#undef IMPL_SHM_ANON
#undef IMPL_SHM_MKSTEMP
#undef IMPL_UNLINK_OR_CLOSE
#ifdef __linux__
#ifdef __NR_memfd_create
#define IMPL_MEMFD
#endif
#endif
#ifdef __FreeBSD__
#define IMPL_SHM_ANON
#endif
#ifdef __HAIKU__
#define IMPL_POSIX
#endif
#ifdef __NetBSD__
#define IMPL_POSIX
#endif
#ifdef __APPLE__
#ifdef __MACH__
#define IMPL_POSIX
#endif
#endif
#ifdef __sun
#define IMPL_POSIX
#endif
#ifdef __DragonFly__
#define IMPL_POSIX
#endif
#ifdef __OpenBSD__
#define IMPL_SHM_MKSTEMP
#endif
#ifdef IMPL_POSIX
#define IMPL_UNLINK_OR_CLOSE
#endif
#ifdef IMPL_SHM_MKSTEMP
#define IMPL_UNLINK_OR_CLOSE
#endif
#ifdef IMPL_UNLINK_OR_CLOSE
static int
shm_unlink_or_close(const char *name, int fd)
{
	int save;

	if (shm_unlink(name) == -1) {
		save = errno;
		close(fd);
		errno = save;
		return -1;
	}
	return fd;
}
#endif
#ifdef IMPL_POSIX
int
shm_open_anon(void)
{
	char name[16] = "/shm-";
	struct timespec tv;
	unsigned long r;
	char *const limit = name + sizeof(name) - 1;
	char *start;
	char *fill;
	int fd, tries;

	*limit = 0;
	start = name + strlen(name);
	for (tries = 0; tries < 4; tries++) {
		clock_gettime(CLOCK_REALTIME, &tv);
		r = (unsigned long)tv.tv_sec + (unsigned long)tv.tv_nsec;
		for (fill = start; fill < limit; r /= 8)
			*fill++ = '0' + (r % 8);
		fd = shm_open(
		  name, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
		if (fd != -1)
			return shm_unlink_or_close(name, fd);
		if (errno != EEXIST)
			break;
	}
	return -1;
}
#endif
#ifdef IMPL_SHM_MKSTEMP
int
shm_open_anon(void)
{
	char name[16] = "/shm-XXXXXXXXXX";
	int fd;

	if ((fd = shm_mkstemp(name)) == -1)
		return -1;
	return shm_unlink_or_close(name, fd);
}
#endif
#ifdef IMPL_SHM_ANON
int
shm_open_anon(void)
{
	return shm_open(SHM_ANON, O_RDWR, 0);
}
#endif
#ifdef IMPL_MEMFD
int
shm_open_anon(void)
{
	return syscall(
	  __NR_memfd_create, "shm_anon", (unsigned int)(MFD_CLOEXEC));
}
#endif