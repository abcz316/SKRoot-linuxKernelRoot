#ifndef _KERNEL_ROOT_KIT_FORK_HELPER_H_
#define _KERNEL_ROOT_KIT_FORK_HELPER_H_
#include <string.h>
#include <iostream>
#include <fstream>
#include <memory>
#include <set>
#include <map>
#include <vector>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>

#define BUF_SIZE 4096
namespace kernel_root {
    class fork_base_info {
    public:
        fork_base_info() { reset(); }
        ~fork_base_info() { close(); }
        int fd_read_parent = -1;
        int fd_write_parent = -1;
        int fd_read_child = -1;
        int fd_write_child = -1;
        pid_t parent_pid = getpid();
        pid_t child_pid = 0;
        
        void reset() {
            close();
            fd_read_parent = -1;
            fd_write_parent = -1;
            fd_read_child = -1;
            fd_write_child = -1;
            parent_pid = getpid();
            child_pid = 0;
        }

        void close() {
            if (fd_read_parent != -1) {
                ::close(fd_read_parent);
                fd_read_parent = -1;
            }
            if (fd_write_parent != -1) {
                ::close(fd_write_parent);
                fd_write_parent = -1;
            }
            if (fd_read_child != -1) {
                ::close(fd_read_child);
                fd_read_child = -1;
            }
            if (fd_write_child != -1) {
                ::close(fd_write_child);
                fd_write_child = -1;
            }
        }
    };
class fork_pipe_info : public fork_base_info {};
static bool fork_pipe_child_process(fork_pipe_info & finfo) {
    int fd_parent_to_child[2]; // 父进程写，子进程读
    int fd_child_to_parent[2]; // 子进程写，父进程读

    if (pipe(fd_parent_to_child) != 0 || pipe(fd_child_to_parent) != 0) {
        return false;
    }

    pid_t pid = fork();
    if (pid < 0) {
        //fork error
        return false;
    }

    finfo.child_pid = pid;
    if(pid == 0) { // Child process
        close(fd_parent_to_child[1]); // Close unused write end
        close(fd_child_to_parent[0]); // Close unused read end
        finfo.fd_read_parent = fd_parent_to_child[0]; // Set up child read end
        finfo.fd_write_child = fd_child_to_parent[1]; // Set up child write end
        return true;
    } else { // Parent process
        close(fd_parent_to_child[0]); // Close unused read end
        close(fd_child_to_parent[1]); // Close unused write end
        finfo.fd_write_parent = fd_parent_to_child[1]; // Set up parent write end
        finfo.fd_read_child = fd_child_to_parent[0]; // Set up parent read end
    }
    return false;
}


static bool wait_fork_child_process(const fork_base_info & finfo) {
	if(finfo.child_pid == 0) {
		return false;
	}
	int status;
	pid_t result = waitpid(finfo.child_pid, &status, WNOHANG | WUNTRACED);
	if (result == 0) {
		// 子进程仍在运行
		return true;
	} else if (result == -1) {
		// 调用失败
		return false;
	} else {
		// 子进程已退出或状态改变
		return true;
	}
}

static bool write_transfer_data_from_child(const fork_pipe_info & finfo, void* data, size_t data_len) {
	if(write(finfo.fd_write_child, &data_len, sizeof(data_len))!=sizeof(data_len)) {
		return false;
	}
	if(data_len == 0) {
		return true;
	}
	if(write(finfo.fd_write_child, data, data_len)!=data_len) {
		return false;
	}
	return false;
}

static bool read_transfer_data_from_child(fork_pipe_info & finfo, void* &data, size_t &data_len) {
	data_len = 0;
	if(read(finfo.fd_read_child , (void*)&data_len, sizeof(data_len))!=sizeof(data_len)) {
		return false;
	}
	if(data_len == 0) {
		return true;
	}
	data = malloc(data_len);
	memset(data, 0, data_len);
	if(read(finfo.fd_read_child , data, data_len)!=data_len) {
		return false;
	}
	return true;
}

static bool write_errcode_from_child(const fork_pipe_info & finfo, ssize_t errCode) {
	if(write(finfo.fd_write_child, &errCode, sizeof(errCode))==sizeof(errCode)) {
		return true;
	}
	return false;
}

static bool read_errcode_from_child(const fork_pipe_info & finfo, ssize_t & errCode) {
	if(read(finfo.fd_read_child, (void*)&errCode, sizeof(errCode))==sizeof(errCode)) {
		return true;
	}
	return false;
}

static bool write_int_from_child(const fork_pipe_info & finfo, int n) {
	if(write(finfo.fd_write_child, &n, sizeof(n))==sizeof(n)) {
		return true;
	}
	return false;
}

static bool read_int_from_child(const fork_pipe_info & finfo, int & n) {
	if(read(finfo.fd_read_child, (void*)&n, sizeof(n))==sizeof(n)) {
		return true;
	}
	return false;
}
static bool write_set_int_from_child(const fork_pipe_info & finfo, const std::set<int> & s) {
	size_t total_size = sizeof(int) * s.size();
	std::vector<char> buffer(total_size);
	char* ptr = buffer.data();

	for (const int &value : s) {
		memcpy(ptr, &value, sizeof(value));
		ptr += sizeof(value);
	}
	return write_transfer_data_from_child(finfo, buffer.data(), total_size);
}

static bool read_set_int_from_child(fork_pipe_info & finfo, std::set<int> & s) {
	void* data = nullptr;
	size_t data_len = 0;

	if (!read_transfer_data_from_child(finfo, data, data_len)) {
		return false;
	}
	if(!data && data_len ==  0) {
		return true;
	}
	char* ptr = static_cast<char*>(data);
	size_t num_elements = data_len / sizeof(int);

	for (size_t i = 0; i < num_elements; i++) {
		int value;
		memcpy(&value, ptr, sizeof(value));
		s.insert(value);
		ptr += sizeof(value);
	}

	free(data);
	return true;
}


static bool write_string_from_child(const fork_pipe_info & finfo, const std::string &text) {
	return write_transfer_data_from_child(finfo, (void*)text.c_str(), text.length());
}

static bool read_string_from_child(fork_pipe_info & finfo, std::string &text) {
	void * data = nullptr;
	size_t len = 0;
	bool r = read_transfer_data_from_child(finfo, data, len);
	if(data) {
		text.assign((char*)data, len);
		free(data);
	}
	return r;
}


static bool write_set_string_from_child(const fork_pipe_info & finfo, const std::set<std::string> &s) {
    size_t total_size = 0;
    for (const auto &str : s) {
        total_size += sizeof(size_t);
        total_size += str.size();
    }

    std::vector<char> buffer(total_size);
    char* ptr = buffer.data();

    for (const auto &str : s) {
        size_t len = str.size();
        memcpy(ptr, &len, sizeof(len));
        ptr += sizeof(len);
        memcpy(ptr, str.data(), len);
        ptr += len;
    }

    return write_transfer_data_from_child(finfo, buffer.data(), total_size);
}


static bool read_set_string_from_child(fork_pipe_info &finfo, std::set<std::string> &s) {
    void* data = nullptr;
    size_t data_len = 0;
    if (!read_transfer_data_from_child(finfo, data, data_len)) {
        return false;
    }
	if(!data && data_len ==  0) {
		return true;
	}

    char* ptr = static_cast<char*>(data);
    char* end = ptr + data_len;

    while (ptr < end) {
        size_t len;
        memcpy(&len, ptr, sizeof(len));
        ptr += sizeof(len);

        std::string str(ptr, len);
        s.insert(str);
        ptr += len;
    }

    free(data);
    return true;
}


static bool write_map_i_s_from_child(const fork_pipe_info & finfo, const std::map<int, std::string> & map) {
    size_t total_size = 0;
    for (const auto &pair : map) {
        total_size += sizeof(int);
        total_size += sizeof(size_t);
        total_size += pair.second.size();
    }

    std::vector<char> buffer(total_size);
    char* ptr = buffer.data();

    for (const auto &pair : map) {
        memcpy(ptr, &(pair.first), sizeof(pair.first));
        ptr += sizeof(pair.first);

        size_t len = pair.second.size();
        memcpy(ptr, &len, sizeof(len));
        ptr += sizeof(len);

        memcpy(ptr, pair.second.data(), len);
        ptr += len;
    }

    return write_transfer_data_from_child(finfo, buffer.data(), total_size);
}

static bool read_map_i_s_from_child(fork_pipe_info & finfo, std::map<int, std::string> & map) {
    void* data = nullptr;
    size_t data_len = 0;
    if (!read_transfer_data_from_child(finfo, data, data_len)) {
        return false;
    }
	if(!data && data_len ==  0) {
		return true;
	}

    char* ptr = static_cast<char*>(data);
    char* end = ptr + data_len;

    while (ptr < end) {
        int key;
        memcpy(&key, ptr, sizeof(key));
        ptr += sizeof(key);

        size_t len;
        memcpy(&len, ptr, sizeof(len));
        ptr += sizeof(len);

        std::string value(ptr, len);
        map[key] = value;
        ptr += len;
    }

    free(data);
    return true;
}

static bool write_map_s_i_from_child(const fork_pipe_info & finfo, const std::map<std::string, int> & map) {
    size_t total_size = 0;
    for (const auto &pair : map) {
        total_size += pair.first.size();
        total_size += sizeof(size_t);
        total_size += sizeof(int);
    }

    std::vector<char> buffer(total_size);
    char* ptr = buffer.data();

    for (const auto &pair : map) {
        size_t len = pair.first.size();
        memcpy(ptr, &len, sizeof(len));
        ptr += sizeof(len);

        memcpy(ptr, pair.first.data(), len);
        ptr += len;

        memcpy(ptr, &(pair.second), sizeof(pair.second));
        ptr += sizeof(pair.second);
    }
    return write_transfer_data_from_child(finfo, buffer.data(), total_size);
}

static bool read_map_s_i_from_child(fork_pipe_info & finfo, std::map<std::string, int> & map) {
    void* data = nullptr;
    size_t data_len = 0;
    if (!read_transfer_data_from_child(finfo, data, data_len)) {
        return false;
    }
	if(!data && data_len ==  0) {
		return true;
	}

    char* ptr = static_cast<char*>(data);
    char* end = ptr + data_len;

    while (ptr < end) {
        size_t len;
        memcpy(&len, ptr, sizeof(len));
        ptr += sizeof(len);

        std::string key(ptr, len);
        ptr += len;
        
        int value;
        memcpy(&value, ptr, sizeof(value));
        map[key] = value;
        ptr += sizeof(value);
    }
    free(data);
    return true;
}


}

#endif /* _KERNEL_ROOT_KIT_FORK_HELPER_H_ */
