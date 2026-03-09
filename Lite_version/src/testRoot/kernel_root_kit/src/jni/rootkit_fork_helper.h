#pragma once
#include <string.h>
#include <unistd.h>
#include <iostream>
#include <map>
#include <set>
#include <vector>
#include <sys/wait.h>

#include "rootkit_err_def.h"

namespace kernel_root {
class fork_base_info {
public:
    fork_base_info() { reset(); }
    ~fork_base_info() { close_all(); }

    fork_base_info(const fork_base_info&) = delete;
    fork_base_info& operator=(const fork_base_info&) = delete;
    fork_base_info(fork_base_info&& o) noexcept { move_from(std::move(o)); }
    fork_base_info& operator=(fork_base_info&& o) noexcept {
        if (this != &o) { close_all(); move_from(std::move(o)); }
        return *this;
    }

    void reset() {
        close_all();
        fd_read_parent  = -1;
        fd_write_parent = -1;
        fd_read_child   = -1;
        fd_write_child  = -1;
        parent_pid = getpid();
        child_pid  = 0;
    }

    void close_all() {
        safe_close(fd_read_parent);
        safe_close(fd_write_parent);
        safe_close(fd_read_child);
        safe_close(fd_write_child);
    }

    int fd_read_parent  = -1;
    int fd_write_parent = -1;
    int fd_read_child   = -1;
    int fd_write_child  = -1;
    pid_t parent_pid = -1;
    pid_t child_pid  = -1;

private:
    static void safe_close(int& fd) {
        if (fd >= 0) { ::close(fd); fd = -1; }
    }
    void move_from(fork_base_info&& o) {
        fd_read_parent  = std::exchange(o.fd_read_parent,  -1);
        fd_write_parent = std::exchange(o.fd_write_parent, -1);
        fd_read_child   = std::exchange(o.fd_read_child,   -1);
        fd_write_child  = std::exchange(o.fd_write_child,  -1);
        parent_pid      = o.parent_pid;
        child_pid       = o.child_pid;
    }
};

class fork_pipe_info : public fork_base_info {};

bool fork_pipe_child_process(fork_pipe_info & finfo);

bool write_transfer_data_from_child(const fork_pipe_info& finfo, const std::vector<uint8_t>& buf);

bool read_transfer_data_from_child(fork_pipe_info& finfo, std::vector<uint8_t>& out);

bool write_errcode_from_child(const fork_pipe_info & finfo, KRootErr e);

bool read_errcode_from_child(const fork_pipe_info & finfo, KRootErr & e);

bool write_int_from_child(const fork_pipe_info & finfo, int n);

bool read_int_from_child(const fork_pipe_info & finfo, int & n);

bool write_uint64_from_child(const fork_pipe_info & finfo, uint64_t n);

bool read_uint64_from_child(const fork_pipe_info & finfo, uint64_t & n);

bool write_set_int_from_child(const fork_pipe_info & finfo, const std::set<int> & s);

bool read_set_int_from_child(fork_pipe_info & finfo, std::set<int> & s);

bool write_string_from_child(const fork_pipe_info & finfo, const std::string &text);

bool read_string_from_child(fork_pipe_info & finfo, std::string &text);

bool write_set_string_from_child(const fork_pipe_info & finfo, const std::set<std::string> &s);

bool read_set_string_from_child(fork_pipe_info &finfo, std::set<std::string> &s);

bool write_map_i_s_from_child(const fork_pipe_info & finfo, const std::map<int, std::string> & map);

bool read_map_i_s_from_child(fork_pipe_info & finfo, std::map<int, std::string> & map);

bool write_map_s_i_from_child(const fork_pipe_info & finfo, const std::map<std::string, int> & map);

bool read_map_s_i_from_child(fork_pipe_info & finfo, std::map<std::string, int> & map);

}
