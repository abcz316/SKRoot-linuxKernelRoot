#pragma once
#include <iostream>
#include <vector>
class KernelVersionParser
{
public:
	KernelVersionParser(const std::vector<char> & file_buf);
	~KernelVersionParser();

public:
	std::string find_kernel_versions();
	bool is_version_less_equal(const std::string& v1, const std::string& v2);
private:
	std::string extract_version(const std::vector<char>& buffer, size_t start_index);
	std::vector<int> parse_version(const std::string& version);
	const std::vector<char>& m_file_buf;
};