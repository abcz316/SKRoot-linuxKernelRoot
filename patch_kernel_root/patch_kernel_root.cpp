// patch_kernel_root.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include "ArmAsmHelper.h"


using namespace std;

struct patch_bytes_data {
	string str_bytes;
	size_t write_addr = 0;
};

char* GetFileBuf(const char* lpszFilePath, int& nSize) {
	FILE* pFile = fopen(lpszFilePath, "rb");
	if (!pFile) {
		return NULL;
	}
	fseek(pFile, 0, SEEK_END);
	nSize = ftell(pFile);
	rewind(pFile);
	char* buffer = (char*)malloc(sizeof(char) * nSize);
	if (!buffer) {
		return NULL;
	}
	size_t result = fread(buffer, 1, nSize, pFile);
	if ((int)result != nSize) {
		free(buffer);
		return NULL;
	}
	fclose(pFile);
	//free(buffer);
	return buffer;
}

void get_rand_str(char* dest, int n) {
	int i, randno;
	char stardstring[63] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	srand((unsigned)time(NULL));
	for (i = 0; i < n; i++) {
		randno = rand() % 62;
		*dest = stardstring[randno];
		dest++;
	}
}

string generate_random_root_key() {
	//生成随机密匙
	const int key_len = 48;
	char root_key_data[key_len] = { 0 };
	get_rand_str(root_key_data, sizeof(root_key_data));
	string str_root_key(root_key_data, sizeof(root_key_data));
	return str_root_key;
}

size_t path_do_execve(const char* file_buf, const string& str_root_key, size_t  hook_func_start_addr,
	size_t do_execve_entry_addr,
	size_t task_struct_offset_cred,
	vector<patch_bytes_data>& vec_out_patch_bytes_data) {

	size_t do_execve_entry_hook_jump_back_addr = do_execve_entry_addr + 4;

	string str_show_root_key_mem_byte = bytesToHexString((const byte*)str_root_key.c_str(), str_root_key.length());
	cout << "#生成的ROOT密匙字节集：" << str_show_root_key_mem_byte.c_str() << endl << endl;
	vec_out_patch_bytes_data.push_back({ str_show_root_key_mem_byte, hook_func_start_addr });

	size_t nHookFuncSize = str_root_key.length();
	hook_func_start_addr += nHookFuncSize;

	stringstream sstrAsm;
	sstrAsm
		<< "MOV X0, X0" << endl
		<< "STP X7, X8, [sp, #-16]!" << endl
		<< "STP X9, X10, [sp, #-16]!" << endl
		<< "STP X11, X12, [sp, #-16]!" << endl
		<< "MOV X7, 0xFFFFFFFFFFFFF001" << endl
		<< "CMP X1, X7" << endl
		<< "BCS #112" << endl
		<< "LDR X7, [X1]" << endl
		<< "CBZ X7, #104" << endl
		<< "ADR X8, #-84" << endl
		<< "MOV X9, #0" << endl
		<< "LDRB W10, [X7, X9]" << endl
		<< "CBZ W10, #88" << endl
		<< "LDRB W11, [X8, X9]" << endl
		<< "CBZ W11, #80" << endl
		<< "CMP W10, W11" << endl
		<< "B.NE #72" << endl
		<< "ADD X9, X9, 1" << endl
		<< "CMP X9, #" << str_root_key.length() << endl
		<< "BLT #-32" << endl
		<< "MRS X8, SP_EL0" << endl
		<< "LDR X8, [X8, #" << task_struct_offset_cred << "]" << endl
		<< "MOV X7, #4" << endl
		<< "MOV W9, WZR" << endl
		<< "STR W9, [X8, X7]" << endl
		<< "ADD X7, X7, 4" << endl
		<< "CMP X7, #36" << endl
		<< "BLT #-12" << endl
		<< "ADD X7, X7, 4" << endl
		<< "MOV X9, 0xFFFFFFFFFFFFFFFF" << endl
		<< "STR X9, [X8, X7]" << endl
		<< "ADD X7, X7, 8" << endl
		<< "CMP X7, #80" << endl
		<< "BLT #-12" << endl
		<< "LDP X11, X12, [sp], #16" << endl
		<< "LDP X9, X10, [sp], #16" << endl
		<< "LDP X7, X8, [sp], #16" << endl
		<< "B #" << do_execve_entry_hook_jump_back_addr - (hook_func_start_addr + 0x94) << endl;
	string strAsmCode = sstrAsm.str();
	cout << endl << strAsmCode << endl;
	string strBytes = AsmToBytes(strAsmCode);
	nHookFuncSize = strBytes.length() / 2;
	char hookOrigCmd[4] = { 0 };
	memcpy(&hookOrigCmd, (void*)((size_t)file_buf + do_execve_entry_addr), sizeof(hookOrigCmd));
	string strHookOrigCmd = bytesToHexString((const byte*)hookOrigCmd, sizeof(hookOrigCmd));
	strBytes = strHookOrigCmd + strBytes.substr(0x4 * 2);
	vec_out_patch_bytes_data.push_back({ strBytes, hook_func_start_addr });
	stringstream sstrAsm2;
	sstrAsm2 << "B #" << hook_func_start_addr - do_execve_entry_addr << endl;
	string strBytes2 = AsmToBytes(sstrAsm2.str());
	vec_out_patch_bytes_data.push_back({ strBytes2, do_execve_entry_addr });
	hook_func_start_addr += nHookFuncSize;
	cout << "#下一段HOOK函数起始可写位置：" << hex << hook_func_start_addr << endl << endl;
	return hook_func_start_addr;
}

size_t path_avc_denied(const char* file_buf, size_t hook_func_start_addr, size_t avc_denied_entry_addr,
	size_t task_struct_offset_cred, vector<patch_bytes_data> & vec_out_patch_bytes_data) {
	size_t avc_denied_entry_hook_jump_back_addr = avc_denied_entry_addr + 4;
	stringstream sstrAsm;
	sstrAsm
		<< "STP X7, X8, [sp, #-16]!" << endl
		<< "STP X9, X10, [sp, #-16]!" << endl
		<< "MRS X7, SP_EL0" << endl
		<< "LDR X7, [X7, #" << task_struct_offset_cred << "]" << endl
		<< "CBZ X7, #84" << endl
		<< "MOV X8, #4" << endl
		<< "MOV W9, WZR" << endl
		<< "LDR W10, [X7, X8]" << endl
		<< "CMP W10, W9" << endl
		<< "B.NE #64" << endl 
		<< "ADD X8, X8, 4" << endl
		<< "CMP X8, #36" << endl
		<< "BLT #-20" << endl
		<< "ADD X8, X8, 12" << endl
		<< "MOV X9, 0x3FFFFFFFFF" << endl
		<< "LDR X10, [X7, X8]" << endl
		<< "ADD X8, X8, 8" << endl
		<< "CMP X10, X9" << endl
		<< "B.CC #28" << endl
		<< "CMP X8, #72" << endl
		<< "BLT #-20" << endl
		<< "LDP X9, X10, [sp], #16" << endl
		<< "LDP X7, X8, [sp], #16" << endl
		<< "MOV W0, WZR" << endl
		<< "RET" << endl
		<< "LDP X9, X10, [sp], #16" << endl
		<< "LDP X7, X8, [sp], #16" << endl
		<< "MOV X0, X0" << endl
		<< "B #" << avc_denied_entry_hook_jump_back_addr - (hook_func_start_addr + 0x70) << endl;
	string strAsmCode = sstrAsm.str();
	cout << endl << strAsmCode << endl;
	string strBytes = AsmToBytes(strAsmCode);
	size_t nHookFuncSize = strBytes.length() / 2;
	char hookOrigCmd[4] = { 0 };
	memcpy(&hookOrigCmd, (void*)((size_t)file_buf + avc_denied_entry_addr), sizeof(hookOrigCmd));
	string strHookOrigCmd = bytesToHexString((const byte*)hookOrigCmd, sizeof(hookOrigCmd));
	strBytes = strBytes.substr(0, (0x6C) * 2) + strHookOrigCmd + strBytes.substr((0x6C + 4) * 2);
	vec_out_patch_bytes_data.push_back({ strBytes, hook_func_start_addr });
	stringstream sstrAsm2;
	sstrAsm2 << "B #" << hook_func_start_addr - avc_denied_entry_addr << endl;
	string strBytes2 = AsmToBytes(sstrAsm2.str());
	vec_out_patch_bytes_data.push_back({ strBytes2, avc_denied_entry_addr });
	return hook_func_start_addr + nHookFuncSize;
}

static auto hex2byte(uint8_t* hex, uint8_t* str) -> void {
	char high, low;
	for (int i = 0, length = strlen((char*)hex); i < length; i += 2) {
		high = toupper(hex[i]) - '0';
		low = toupper(hex[i + 1]) - '0';
		str[i / 2] = ((high > 9 ? high - 7 : high) << 4) + (low > 9 ? low - 7 : low);
	}
}

bool write_file_bytes(const char* file_path, long offset, const char* bytes, int len) {
	FILE* pFile = fopen(file_path, "rb+");
	if (!pFile) {
		return false;
	}
	fseek(pFile, offset, SEEK_SET);
	fwrite(bytes, len, 1, pFile);
	fclose(pFile);
	return true;
}

int main(int argc, char* argv[]) {
	++argv;
	--argc;

	cout << "本工具用于生成aarch64 Linux内核ROOT提权HOOK代码" << endl << endl;

	if (argc < 1) {
		cout << "无输入文件" << endl;
		system("pause");
		return 0;
	}

	int nFileSize = 0;
	const char* file_path = argv[0];
	char* image = GetFileBuf(file_path, nFileSize);
	if (!image) {
		cout << "打开文件失败:" << file_path << endl;
		system("pause");
		return 0;
	}

	//cout << "请输入空闲代码的位置：（即存放执行HOOK代码的位置）：" << endl;
	size_t hook_func_start_addr = 0x300;
	//cin >> hex >> hook_func_start_addr;

	size_t do_execve_entry_addr = 0;
	cout << "请输入do_execve函数的入口位置：" << endl;
	cin >> hex >> do_execve_entry_addr;

	size_t avc_denied_entry_addr = 0;
	cout << "请输入avc_denied函数的入口位置：" << endl;
	cin >> hex >> avc_denied_entry_addr;

	size_t task_struct_offset_cred = -1;
	while (task_struct_offset_cred % 8) {
		cout << "请输入task_struct结构体里cred的十六进制偏移值（从setresuid的头部能看到）：" << endl;
		cin >> hex >> task_struct_offset_cred;
		if (task_struct_offset_cred % 8) {
			cout << "信息输入有误" << endl;
		}
	}

	string str_root_key;
	size_t create_new_root_key = 0;
	cout << "是否需要自动随机生成ROOT密匙（1需要；2不需要）：" << endl;
	cin >> hex >> create_new_root_key;
	if (create_new_root_key == 1) {
		str_root_key = generate_random_root_key();
	} else {
		cout << "请输入ROOT密匙（48个字符的字符串，包含大小写和数字）：" << endl;
		cin >> str_root_key;
	}
	vector<patch_bytes_data> vec_patch_bytes_data;
	hook_func_start_addr = path_do_execve(image, str_root_key, hook_func_start_addr, do_execve_entry_addr, task_struct_offset_cred, vec_patch_bytes_data);
	path_avc_denied(image, hook_func_start_addr, avc_denied_entry_addr, task_struct_offset_cred, vec_patch_bytes_data);

	cout << "#获取ROOT权限的密匙：" << str_root_key.c_str() << endl << endl;

	size_t need_write_modify_in_file = 0;
	cout << "#是否需要立即写入修改到文件？（1需要；2不需要）：" << endl;
	cin >> need_write_modify_in_file;
	if (need_write_modify_in_file == 1) {
		for (auto& item : vec_patch_bytes_data) {
			shared_ptr<char> spData(new (std::nothrow) char[item.str_bytes.length() / 2], std::default_delete<char[]>());
			hex2byte((uint8_t*)item.str_bytes.c_str(), (uint8_t*)spData.get());
			write_file_bytes(file_path, item.write_addr, spData.get(), item.str_bytes.length() / 2);
		}
	}
	free(image);
	system("pause");
	return 0;
}