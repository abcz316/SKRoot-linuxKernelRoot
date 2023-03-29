#ifndef _SU_H_
#define _SU_H_
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <pwd.h>
#include <dirent.h>
#include <time.h>
#include <iostream>
#include <memory>
#include <vector>
#include <map>

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <fcntl.h>
#include <getopt.h>
#include <stdarg.h>
#include <pthread.h>
#include <sched.h>
#include <termios.h>
#include <signal.h>
#include <libgen.h>
#include <poll.h>

#define DEFAULT_SHELL "/system/bin/sh"

// Constants for atty
#define ATTY_IN    (1 << 0)
#define ATTY_OUT   (1 << 1)
#define ATTY_ERR   (1 << 2)

#define UID_ROOT   0
#define UID_SHELL  2000

#define ROOT_VER_CODE 1
#define ROOT_VERSION "1.0"

struct su_req_base {
	int uid = UID_ROOT;
	bool login = false;
	bool keepenv = false;
	bool mount_master = false;
} __attribute__((packed));

struct su_request : public su_req_base {
	std::string shell = DEFAULT_SHELL;
	std::string command;
};

#endif /* _SU_H_ */
