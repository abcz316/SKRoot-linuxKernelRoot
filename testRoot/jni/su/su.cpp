#include "su.h"
#include "su_log.h"
#include "su_hide_path_utils.h"
#include "kernel_root_kit/kernel_root_kit_command.h"
#include <filesystem>

namespace {
	std::string get_executable_directory() {
		char processdir[4096] = { 0 };
		ssize_t path_len = readlink("/proc/self/exe", processdir, sizeof(processdir));
		if(path_len > 0) {
			std::filesystem::path path(processdir);
			return path.parent_path().string();
		}
		return {};
	}

	/*
	 * Bionic's atoi runs through strtol().
	 * Use our own implementation for faster conversion.
	 */
	int parse_int(const char* s) {
		int val = 0;
		char c;
		while ((c = *(s++))) {
			if (c > '9' || c < '0')
				return -1;
			val = val * 10 + c - '0';
		}
		return val;
	}

	// Set effective uid back to root, otherwise setres[ug]id will fail if uid isn't root
	void set_identity(unsigned uid) {
		if (seteuid(0)) {
			SU_PRINTF("seteuid (root)");
		}
		if (setresgid(uid, uid, uid)) {
			SU_PRINTF("setresgid (%u)", uid);
		}
		if (setresuid(uid, uid, uid)) {
			SU_PRINTF("setresuid (%u)", uid);
		}
	}
}

void usage(int status) {
	FILE* stream = (status == EXIT_SUCCESS) ? stdout : stderr;

	fprintf(stream,
		"linux kernel root\n\n"
		"Usage: su [options] [-] [user [argument...]]\n\n"
		"Options:\n"
		"  -c, --command COMMAND         pass COMMAND to the invoked shell\n"
		"  -h, --help                    display this help message and exit\n"
		"  -, -l, --login                pretend the shell to be a login shell\n"
		"  -m, -p,\n"
		"  --preserve-environment        preserve the entire environment\n"
		"  -s, --shell SHELL             use SHELL instead of the default " DEFAULT_SHELL "\n"
		"  -v, --version                 display version number and exit\n"
		"  -V                            display version code and exit\n"
		"  -mm, -M,\n"
		"  --mount-master                force run in the global mount namespace\n\n");
	exit(status);
}

static inline std::string get_root_key() {
	std::string myself_path = get_executable_directory();
	std::string str_root_key = kernel_root::su::parse_root_key_by_su_path(myself_path.c_str());
	return str_root_key;
}

int su_client_main(int argc, char* argv[]) {
	int c;
	struct option long_opts[] = {
		{ "command",                required_argument,  nullptr, 'c' },
		{ "help",                   no_argument,        nullptr, 'h' },
		{ "login",                  no_argument,        nullptr, 'l' },
		{ "preserve-environment",   no_argument,        nullptr, 'p' },
		{ "shell",                  required_argument,  nullptr, 's' },
		{ "version",                no_argument,        nullptr, 'v' },
		{ "context",                required_argument,  nullptr, 'z' },
		{ "mount-master",           no_argument,        nullptr, 'M' },
		{ nullptr, 0, nullptr, 0 },
	};

	su_request su_req;

	for (int i = 0; i < argc; i++) {
		// Replace -cn with -z, -mm with -M for supporting getopt_long
		if (strcmp(argv[i], "-cn") == 0)
			strcpy(argv[i], "-z");
		else if (strcmp(argv[i], "-mm") == 0)
			strcpy(argv[i], "-M");
	}

	while ((c = getopt_long(argc, argv, "c:hlmps:Vvuz:M", long_opts, nullptr)) != -1) {
		switch (c) {
		case 'c':
			for (int i = optind - 1; i < argc; ++i) {
				if (!su_req.command.empty())
					su_req.command += ' ';
				su_req.command += argv[i];
			}
			optind = argc;
			break;
		case 'h':
			usage(EXIT_SUCCESS);
			break;
		case 'l':
			su_req.login = true;
			break;
		case 'm':
		case 'p':
			su_req.keepenv = true;
			break;
		case 's':
			su_req.shell = optarg;
			break;
		case 'V':
			printf("%d\n", ROOT_VER_CODE);
			exit(EXIT_SUCCESS);
		case 'v':
			printf("%s\n", ROOT_VERSION);
			exit(EXIT_SUCCESS);
		case 'z':
			// Do nothing, placed here for legacy support :)
			break;
		case 'M':
			su_req.mount_master = true;
			break;
		default:
			/* Bionic getopt_long doesn't terminate its error output by newline */
			fprintf(stderr, "\n");
			usage(2);
		}
	}

	if (optind < argc && strcmp(argv[optind], "-") == 0) {
		su_req.login = true;
		optind++;
	}

	std::string root_key = get_root_key();
	SU_PRINTF("root_key:%s\n", root_key.c_str());

	if (fork() == 0) {
		kernel_root::get_root(root_key.c_str());
		SU_PRINTF("current uid:%d\n", getuid());

		/* username or uid */
		if (optind < argc) {
			struct passwd* pw;
			pw = getpwnam(argv[optind]);
			if (pw) {
				su_req.uid = pw->pw_uid;
			} else {
				su_req.uid = parse_int(argv[optind]);
			}
			optind++;
		}
		struct passwd* pw = getpwuid(su_req.uid);
		if (pw) {
			setenv("HOME", pw->pw_dir, 1);
			setenv("USER", pw->pw_name, 1);
			setenv("LOGNAME", pw->pw_name, 1);
			setenv("SHELL", su_req.shell.data(), 1);
		}

		const char* new_argv[4] = { nullptr };
		new_argv[0] = su_req.login ? "-" : su_req.shell.data();

		if (!su_req.command.empty()) {
			new_argv[1] = "-c";
			new_argv[2] = su_req.command.data();
		}

		// If you need it, you can unblock this line of code yourself
		//set_identity(su_req.uid);

		execvp(su_req.shell.data(), (char**)new_argv);
	} else {
		wait(NULL);
	}
	exit(0);
	return 0;
}

int main(int argc, char* argv[]) {
	return su_client_main(argc, argv);
}
