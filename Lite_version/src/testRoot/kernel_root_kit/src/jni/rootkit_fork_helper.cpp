#include <string.h>
#include <unistd.h>
#include <iostream>
#include <fstream>
#include <memory>
#include <set>
#include <map>
#include <vector>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include "rootkit_umbrella.h"
#include "rootkit_fork_helper.h"

namespace kernel_root {
bool fork_pipe_child_process(fork_pipe_info & finfo) {
    int p2c[2] = {-1, -1};
    int c2p[2] = {-1, -1};
    if (pipe2(p2c, O_CLOEXEC) == -1) return false;
    if (pipe2(c2p, O_CLOEXEC) == -1) {
        ::close(p2c[0]); ::close(p2c[1]);
        return false;
    }

    pid_t pid = fork();
    if (pid < 0) {
        ::close(p2c[0]); ::close(p2c[1]);
        ::close(c2p[0]); ::close(c2p[1]);
        return false;
    }

    if(pid == 0) { // Child process
        ::close(p2c[1]);
        ::close(c2p[0]);
        finfo.parent_pid     = getppid();
        finfo.child_pid      = 0;
        finfo.fd_read_parent = p2c[0];
        finfo.fd_write_child = c2p[1];
        finfo.fd_write_parent = -1;
        finfo.fd_read_child   = -1;
        return true;
    } else { // Parent process
        ::close(p2c[0]);
        ::close(c2p[1]);
        finfo.child_pid      = pid;
        finfo.parent_pid     = getpid();
        finfo.fd_write_parent = p2c[1];
        finfo.fd_read_child   = c2p[0];
        finfo.fd_read_parent  = -1;
        finfo.fd_write_child  = -1;
        return false;
    }
}

static bool write_full(int fd, const void* buf, size_t len) {
    const char* p = static_cast<const char*>(buf);
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n > 0) { p += n; len -= (size_t)n; continue; }
        if (n == -1 && errno == EINTR) continue;
        if (n == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            usleep(1000*1);
            continue;
        }
        return false;
    }
    return true;
}

static bool read_full(int fd, void* buf, size_t len) {
    char* p = static_cast<char*>(buf);
    while (len > 0) {
        ssize_t n = read(fd, p, len);
        if (n > 0) { p += n; len -= (size_t)n; continue; }
        if (n == 0) return false;  
        if (n == -1 && errno == EINTR) continue;
        if (n == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            usleep(1000*1);
            continue;
        }
        return false;
    }
    return true;
}

bool write_transfer_data_from_child(const fork_pipe_info& finfo, const std::vector<uint8_t>& buf) {
    const uint64_t n = static_cast<uint64_t>(buf.size());
    if (!write_full(finfo.fd_write_child, &n, sizeof(n))) return false;
    if (n == 0) return true;
    return write_full(finfo.fd_write_child, buf.data(), buf.size());
}

bool read_transfer_data_from_child(fork_pipe_info& finfo, std::vector<uint8_t>& out) {
    out.clear();
    uint64_t n = 0;
    if (!read_full(finfo.fd_read_child, &n, sizeof(n))) return false;
    if (n == 0) return true;
    if (n > SIZE_MAX) return false;
    out.resize(static_cast<size_t>(n));
    return read_full(finfo.fd_read_child, out.data(), out.size());
}

bool write_errcode_from_child(const fork_pipe_info& finfo, KRootErr e) {
    return write_full(finfo.fd_write_child, &e, sizeof(e));
}

bool read_errcode_from_child(const fork_pipe_info& finfo, KRootErr& e) {
    return read_full(finfo.fd_read_child, &e, sizeof(e));
}

bool write_int_from_child(const fork_pipe_info& finfo, int n) {
    return write_full(finfo.fd_write_child, &n, sizeof(n));
}

bool read_int_from_child(const fork_pipe_info& finfo, int& n) {
    return read_full(finfo.fd_read_child, &n, sizeof(n));
}

bool write_uint64_from_child(const fork_pipe_info& finfo, uint64_t n) {
    return write_full(finfo.fd_write_child, &n, sizeof(n));
}

bool read_uint64_from_child(const fork_pipe_info& finfo, uint64_t& n) {
    return read_full(finfo.fd_read_child, &n, sizeof(n));
}

bool write_set_int_from_child(const fork_pipe_info & finfo, const std::set<int> & s) {
	size_t total_size = sizeof(int) * s.size();
	std::vector<uint8_t> buf(total_size);
	uint8_t* ptr = buf.data();

	for (const int &value : s) {
		memcpy(ptr, &value, sizeof(value));
		ptr += sizeof(value);
	}
	return write_transfer_data_from_child(finfo, buf);
}

bool read_set_int_from_child(fork_pipe_info & finfo, std::set<int> & s) {
    std::vector<uint8_t> buf;
    if (!read_transfer_data_from_child(finfo, buf)) return false;
	if(buf.empty()) return true;

	uint8_t* ptr = static_cast<uint8_t*>(buf.data());
	size_t num_elements = buf.size() / sizeof(int);
	for (size_t i = 0; i < num_elements; i++) {
		int value;
		memcpy(&value, ptr, sizeof(value));
		s.insert(value);
		ptr += sizeof(value);
	}
	return true;
}

bool write_string_from_child(const fork_pipe_info& finfo, const std::string& s) {
    const std::vector<uint8_t> buf(reinterpret_cast<const uint8_t*>(s.data()),
                                   reinterpret_cast<const uint8_t*>(s.data()) + s.size());
    return write_transfer_data_from_child(finfo, buf);
}

bool read_string_from_child(fork_pipe_info& finfo, std::string& s) {
    std::vector<uint8_t> buf;
    if (!read_transfer_data_from_child(finfo, buf)) return false;
    s.assign(reinterpret_cast<const char*>(buf.data()), buf.size());
    return true;
}

bool write_set_string_from_child(const fork_pipe_info & finfo, const std::set<std::string> &s) {
    size_t total_size = 0;
    for (const auto &str : s) {
        total_size += sizeof(size_t);
        total_size += str.size();
    }

    std::vector<uint8_t> buf(total_size);
    uint8_t* ptr = buf.data();

    for (const auto &str : s) {
        size_t len = str.size();
        memcpy(ptr, &len, sizeof(len));
        ptr += sizeof(len);
        memcpy(ptr, str.data(), len);
        ptr += len;
    }

    return write_transfer_data_from_child(finfo, buf);
}

bool read_set_string_from_child(fork_pipe_info &finfo, std::set<std::string> &s) {
    std::vector<uint8_t> buf;
    if (!read_transfer_data_from_child(finfo, buf)) return false;
	if(buf.empty()) return true;

    uint8_t* ptr = static_cast<uint8_t*>(buf.data());
    uint8_t* end = ptr + buf.size();

    while (ptr < end) {
        size_t len;
        memcpy(&len, ptr, sizeof(len));
        ptr += sizeof(len);

        std::string str((char*)ptr, len);
        s.insert(str);
        ptr += len;
    }
    return true;
}


bool write_map_i_s_from_child(const fork_pipe_info & finfo, const std::map<int, std::string> & map) {
    size_t total_size = 0;
    for (const auto &pair : map) {
        total_size += sizeof(int);
        total_size += sizeof(size_t);
        total_size += pair.second.size();
    }

    std::vector<uint8_t> buf(total_size);
    uint8_t* ptr = buf.data();

    for (const auto &pair : map) {
        memcpy(ptr, &(pair.first), sizeof(pair.first));
        ptr += sizeof(pair.first);

        size_t len = pair.second.size();
        memcpy(ptr, &len, sizeof(len));
        ptr += sizeof(len);

        memcpy(ptr, pair.second.data(), len);
        ptr += len;
    }

    return write_transfer_data_from_child(finfo, buf);
}

bool read_map_i_s_from_child(fork_pipe_info & finfo, std::map<int, std::string> & map) {
    std::vector<uint8_t> buf;
    if (!read_transfer_data_from_child(finfo, buf)) return false;
	if(buf.empty()) return true;

    uint8_t* ptr = static_cast<uint8_t*>(buf.data());
    uint8_t* end = ptr + buf.size();

    while (ptr < end) {
        int key;
        memcpy(&key, ptr, sizeof(key));
        ptr += sizeof(key);

        size_t len;
        memcpy(&len, ptr, sizeof(len));
        ptr += sizeof(len);

        std::string value((char*)ptr, len);
        map[key] = value;
        ptr += len;
    }
    return true;
}

bool write_map_s_i_from_child(const fork_pipe_info & finfo, const std::map<std::string, int> & map) {
    size_t total_size = 0;
    for (const auto &pair : map) {
        total_size += pair.first.size();
        total_size += sizeof(size_t);
        total_size += sizeof(int);
    }

    std::vector<uint8_t> buf(total_size);
    uint8_t* ptr = buf.data();

    for (const auto &pair : map) {
        size_t len = pair.first.size();
        memcpy(ptr, &len, sizeof(len));
        ptr += sizeof(len);

        memcpy(ptr, pair.first.data(), len);
        ptr += len;

        memcpy(ptr, &(pair.second), sizeof(pair.second));
        ptr += sizeof(pair.second);
    }
    return write_transfer_data_from_child(finfo, buf);
}

bool read_map_s_i_from_child(fork_pipe_info & finfo, std::map<std::string, int> & map) {
    std::vector<uint8_t> buf;
    if (!read_transfer_data_from_child(finfo, buf)) return false;
	if(buf.empty()) return true;

    uint8_t* ptr = static_cast<uint8_t*>(buf.data());
    uint8_t* end = ptr + buf.size();

    while (ptr < end) {
        size_t len;
        memcpy(&len, ptr, sizeof(len));
        ptr += sizeof(len);

        std::string key((char*)ptr, len);
        ptr += len;
        
        int value;
        memcpy(&value, ptr, sizeof(value));
        map[key] = value;
        ptr += sizeof(value);
    }
    return true;
}
}