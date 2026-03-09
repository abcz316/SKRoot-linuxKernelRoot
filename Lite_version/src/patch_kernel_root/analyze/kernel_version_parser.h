#pragma once
#include <iostream>
#include <vector>
class KernelVersionParser
{
public:
	KernelVersionParser(const std::vector<char> & file_buf);
	~KernelVersionParser();

public:
	std::string get_kernel_version() const;
	bool is_kernel_version_less(const std::string& ver) const;
private:
	std::string find_kernel_versions() const;
	std::string extract_version(const std::vector<char>& buffer, size_t start_index) const;
	bool is_version_less(const std::string& v1, const std::string& v2) const;
	std::vector<int> parse_version(const std::string& version) const;

	const std::vector<char>& m_file_buf;
	std::string m_ver;
};