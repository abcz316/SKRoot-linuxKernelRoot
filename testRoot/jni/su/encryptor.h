#ifndef _SU_ENCRYPTOR_H_
#define _SU_ENCRYPTOR_H_
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <sstream>
#include <iomanip>
namespace {
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
static std::string encryp_string(const std::string& src, const std::string& key, bool random = true) {
	int KeyPos = -1;
	int SrcAsc = 0;
	time_t t;

	int KeyLen = key.length();
	if (KeyLen == 0)
		return "";

	
	int offset;
	if(random) {
		srand((unsigned)time(&t));
		offset = rand() % 255;
	} else {
		offset = 128;
	}

	std::stringstream ss;
	ss << std::hex << std::setw(2) << std::setfill('0') << offset;

	for (int i = 0; i < src.length(); i++) {
		SrcAsc = (src[i] + offset) % 255;

		if (KeyPos < KeyLen - 1)
			KeyPos++;
		else
			KeyPos = 0;

		SrcAsc = SrcAsc ^ key[KeyPos];

		ss << std::hex << std::setw(2) << std::setfill('0') << SrcAsc;

		offset = SrcAsc;
	}
	return ss.str();
}

static std::string uncryp_string(const std::string& src, const std::string& key) {
	int KeyLen = key.length();
	if (KeyLen == 0)
		return {};

	int KeyPos = -1;
	int offset = 0;
	std::string dest;
	int SrcAsc = 0;
	int TmpSrcAsc = 0;

	std::stringstream ss;
	ss << std::hex << src.substr(0, 2);
	ss >> offset;
	int SrcPos = 2;
	while (SrcPos < src.length()) {
		ss.clear();
		ss << std::hex << src.substr(SrcPos, 2);
		ss >> SrcAsc;
		if (KeyPos < KeyLen - 1)
			KeyPos++;
		else
			KeyPos = 0;

		TmpSrcAsc = SrcAsc ^ key[KeyPos];

		if (TmpSrcAsc <= offset)
			TmpSrcAsc = 255 + TmpSrcAsc - offset;
		else
			TmpSrcAsc = TmpSrcAsc - offset;

		dest += char(TmpSrcAsc);
		offset = SrcAsc;
		SrcPos += 2;
	}

	return dest;
}
}
#endif /* _SU_ENCRYPTOR_H_ */
