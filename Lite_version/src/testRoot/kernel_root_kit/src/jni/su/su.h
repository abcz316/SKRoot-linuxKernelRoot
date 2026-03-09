#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pwd.h>
#include <getopt.h>
#include <sys/types.h>
#include <string>

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
