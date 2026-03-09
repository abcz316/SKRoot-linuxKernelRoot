#ifndef URL_ENCODE_UTILS_H_
#define URL_ENCODE_UTILS_H_
#include <ctype.h>
#include <stdio.h>

static inline char to_hex(char code) {
	static char hex[] = "0123456789ABCDEF";
	return hex[code & 15];
}
static inline char from_hex(char ch) {
	return isdigit(ch) ? ch - '0' : tolower(ch) - 'a' + 10;
}

/*
//使用例子
int main() {
	char str[] = "你好，世界";
	char encoded_str[256];
	url_encode(str, encoded_str);
	printf("Encoded URL: %s\n", encoded_str);
	return 0;
}
*/
static void url_encode(char *str, char *encoded_str) {
	char *pstr = str, *buf = encoded_str;
	while (*pstr) {
		unsigned char c = *pstr;
		if (c <= 0x7F) { // ASCII
			if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
				*buf++ = c;
			} else if (c == ' ') {
				*buf++ = '+';
			} else {
				*buf++ = '%', *buf++ = to_hex(c >> 4), *buf++ = to_hex(c & 15);
			}
		} else { // Non-ASCII
			while (c) {
				*buf++ = '%', *buf++ = to_hex(c >> 4), *buf++ = to_hex(c & 15);
				c = *(++pstr);
			}
			continue;
		}
		pstr++;
	}
	*buf = '\0';
}
/*
//使用例子
int main() {
	char url[] = "%E4%BD%A0%E5%A5%BD%EF%BC%8C%E4%B8%96%E7%95%8C";  // "你好，世界"的URL编码
	char decoded_str[256];
	url_decode(url, decoded_str);
	printf("Decoded URL: %s\n", decoded_str);
	return 0;
}
*/
static void url_decode(char *str, char *decoded_str) {
	char *pstr = str, *buf = decoded_str;
	while (*pstr) {
		if (*pstr == '%') {
			if (pstr[1] && pstr[2]) {
				*buf++ = from_hex(pstr[1]) << 4 | from_hex(pstr[2]);
				pstr += 2;
			}
		} else if (*pstr == '+') { 
			*buf++ = ' ';
		} else {
			*buf++ = *pstr;
		}
		pstr++;
	}
	*buf = '\0';
}
#endif