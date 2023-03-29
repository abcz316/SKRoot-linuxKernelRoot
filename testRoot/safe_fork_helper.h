#ifndef _SAFE_FORK_HELPER_H_
#define _SAFE_FORK_HELPER_H_
#include <string.h>
#include <iostream>
#include <fstream>
#include <memory>
#include <vector>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>

class fork_base_info {
public:
	fork_base_info() { reset(); }
	~fork_base_info() { close();	}
	int fd_read = -1;
	int fd_write = -1;
	pid_t pid = 0;
	void reset() {
		close();
		fd_read = -1;
		fd_write = -1;
		pid = 0;
	}
	void close() {
		if (fd_read != -1) {
			::close(fd_read);
			fd_read = -1;
		}
		if (fd_write != -1) {
			::close(fd_write);
			fd_write = -1;
		}
	}
};
class fork_pipe_info : public fork_base_info {};
static bool fork_pipe_child_process(fork_pipe_info & finfo) {
	int fd[2];
	if (pipe(fd)) {
		return false;
	}
	pid_t pid;
	if ((pid = fork()) < 0) {
		//fork error
		return false;
	}
	finfo.pid = pid;
	if(pid == 0) { // child process
		close(fd[0]); //close read pipe
		finfo.fd_read = -1;
		finfo.fd_write = fd[1];
		return true;
	}
	// father process
	close(fd[1]); //close write pipe
	finfo.fd_read = fd[0];
	finfo.fd_write = -1;
	return false;
}

static bool wait_fork_child_process(const fork_base_info & finfo) {
	if(finfo.pid == 0) {
		return false;
	}
	int status;
	if (waitpid(finfo.pid, &status, WUNTRACED) < 0) {
		return false;
	}
	return true;
}

static bool write_errcode_to_father(const fork_pipe_info & finfo, ssize_t errCode) {
	if(write(finfo.fd_write, &errCode, sizeof(errCode))==sizeof(errCode)) {
		return true;
	}
	return false;
}

static bool read_errcode_from_child(const fork_pipe_info & finfo, ssize_t & errCode) {
	if(read(finfo.fd_read, (void*)&errCode, sizeof(errCode))==sizeof(errCode)) {
		return true;
	}
	return false;
}

static bool write_int_to_father(const fork_pipe_info & finfo, int n) {
	if(write(finfo.fd_write, &n, sizeof(n))==sizeof(n)) {
		return true;
	}
	return false;
}

static bool read_int_from_child(const fork_pipe_info & finfo, int & n) {
	if(read(finfo.fd_read, (void*)&n, sizeof(n))==sizeof(n)) {
		return true;
	}
	return false;
}

static bool write_vec_int_to_father(const fork_pipe_info & finfo, const std::vector<int> & v) {
	size_t len = v.size();
	if(write(finfo.fd_write, &len, sizeof(len))!=sizeof(len)) {
		return false;
	}
	for(int i : v) {
		if(write(finfo.fd_write, &i, sizeof(i))!=sizeof(i)) {
			return false;
		}
	}
	return true;
}

static bool read_vec_int_from_child(const fork_pipe_info & finfo, std::vector<int> & v) {
	size_t len = 0;
	if(read(finfo.fd_read, (void*)&len, sizeof(len))!=sizeof(len)) {
		return false;
	}
	for(size_t i = 0; i < len; i++) {
		int n = 0;
		if(read(finfo.fd_read, (void*)&n, sizeof(n))!=sizeof(n)) {
			return false;
		}
		v.push_back(n);
	}
	return true;
}

static bool write_string_to_father(const fork_pipe_info & finfo, const std::string &text) {
	size_t len = text.length();
	if(write(finfo.fd_write, &len, sizeof(len))!=sizeof(len)) {
		return false;
	}
	if(write(finfo.fd_write, text.c_str(), len)!=len) {
		return false;
	}
	return true;
}

static bool read_string_from_child(const fork_pipe_info & finfo, std::string &text) {
	size_t len = 0;
	if(read(finfo.fd_read, (void*)&len, sizeof(len))!=sizeof(len)) {
		return false;
	}
	std::shared_ptr<char> sp_buf(new (std::nothrow) char[len], std::default_delete<char[]>());
	if (!sp_buf) {
		return false;
	}
	if(read(finfo.fd_read, sp_buf.get(), len)!=len) {
		return false;
	}
	text.assign(sp_buf.get(), len);
	return true;
}

class fork_socketpair_info : public fork_pipe_info {};
static bool fork_socketpair_child_process(fork_socketpair_info & finfo) {
	int fd[2];
	if (socketpair(PF_UNIX, SOCK_DGRAM, 0, fd) < 0) {
		return false;
	}
	pid_t pid;
	if ((pid = fork()) < 0) {
		//fork error
		return false;
	}
	finfo.pid = pid;
	if(pid == 0) { // child process
		close(fd[0]); //close read pipe
		finfo.fd_read = -1;
		finfo.fd_write = fd[1];
		return true;
	}
	// father process
	close(fd[1]); //close write pipe
	finfo.fd_read = fd[0];
	finfo.fd_write = -1;
	return false;
}

static bool write_fd_to_father(const fork_socketpair_info & finfo, int fd) {
	iovec iov[1];
	msghdr msg;
	char buff[0];

	//指定缓冲区
	iov[0].iov_base = buff;
	iov[0].iov_len = 1;

	//通过socketpair进行通信，不需要知道ip地址
	msg.msg_name = nullptr;
	msg.msg_namelen = 0;

	//指定内存缓冲区
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

	//辅助数据
	cmsghdr cm;
	cm.cmsg_len = CMSG_LEN(sizeof(fd)); //描述符的大小
	cm.cmsg_level = SOL_SOCKET;         //表示传递的辅助数据是文件描述符
	cm.cmsg_type = SCM_RIGHTS;          //协议类型
	*(int*)CMSG_DATA(&cm) = fd; //设置待发送描述符

	//设置辅助数据
	msg.msg_control = &cm;
	msg.msg_controllen = CMSG_LEN(sizeof(fd));

	if(sendmsg(finfo.fd_write, &msg, 0) == -1) {
		return false;
	}
	return true;
}

static bool read_fd_from_child(const fork_socketpair_info & finfo, int & fd) {
	iovec iov[1];
	msghdr msg;
	char buff[0];

	//指定缓冲区
	iov[0].iov_base = buff;
	iov[0].iov_len = 1;

	//通过socketpair进行通信，不需要知道ip地址
	msg.msg_name = nullptr;
	msg.msg_namelen = 0;

	//指定内存缓冲区
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

	//辅助数据
	cmsghdr cm;

	//设置辅助数据
	msg.msg_control = &cm;
	msg.msg_controllen = CMSG_LEN(sizeof(fd));

	if(recvmsg(finfo.fd_read, &msg, 0) == -1) {
		return false;
	}

	fd = *(int*)CMSG_DATA(&cm);
	return true;
}

#endif /* _SAFE_FORK_HELPER_H_ */
