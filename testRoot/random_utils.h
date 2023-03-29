#ifndef _RANDOM_UTILS_H_
#define _RANDOM_UTILS_H_
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <sstream>

/*生成随机数*/
static void rand_str(char* dest, int n) {
	int i, randno;
	char stardstring[63] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	srand((unsigned)time(NULL));
	for (i = 0; i < n; i++) {
		randno = rand() % 62;
		*dest = stardstring[randno];
		dest++;
	}
}

#endif /* _RANDOM_UTILS_H_ */
