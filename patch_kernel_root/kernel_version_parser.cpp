#pragma once
#include "kernel_version_parser.h"
#include <sstream>

#ifndef MIN
#define MIN(x, y)(x < y) ? (x) : (y)
#endif // !MIN

KernelVersionParser::KernelVersionParser(const std::vector<char>& file_buf) : m_file_buf(file_buf)
{
}

KernelVersionParser::~KernelVersionParser()
{
}

// Helper function to extract and print the version number starting from the given index
std::string KernelVersionParser::extract_version(const std::vector<char>& buffer, size_t start_index) {
	std::string version;
	// Extract until we hit a non-version character or end of buffer
	while (start_index < buffer.size() && (isdigit(buffer[start_index]) || buffer[start_index] == '.')) {
		version.push_back(buffer[start_index]);
		++start_index;
	}
	return version;
}

// Function to search for Linux version patterns using memcmp
std::string KernelVersionParser::find_kernel_versions() {
	const size_t safe_end = MIN(m_file_buf.size(), 256);
	const char* prefix = "Linux version ";
	const size_t prefix_len = strlen(prefix);

	for (size_t i = 0; i + prefix_len <= m_file_buf.size() - safe_end; ++i) {
		if (memcmp(m_file_buf.data() + i, prefix, prefix_len) == 0 && isdigit(m_file_buf[i + prefix_len])) {
			return extract_version(m_file_buf, i + prefix_len);
		}
	}
	return {};
}


// Helper function to split the version string and convert to integers
std::vector<int> KernelVersionParser::parse_version(const std::string& version) {
	std::vector<int> parts;
	std::stringstream ss(version);
	std::string part;

	while (getline(ss, part, '.')) {
		parts.push_back(std::stoi(part));
	}
	// Ensure we always have at least three parts (fill missing parts with zero)
	while (parts.size() < 3) {
		parts.push_back(0);
	}

	return parts;
}

// Function to compare two version numbers
bool KernelVersionParser::is_version_less_equal(const std::string& v1, const std::string& v2) {
	auto parts1 = parse_version(v1);
	auto parts2 = parse_version(v2);

	// Compare major, minor, and patch versions
	for (int i = 0; i < 3; ++i) {
		if (parts1[i] < parts2[i]) return true;
		if (parts1[i] > parts2[i]) return false;
	}

	// If all parts are equal
	return true;
}
