#pragma once
#include "file_manager_api.h"
#include <functional>
#include <mutex>
#include <string>
#include <sys/types.h>

namespace file_manager {
// Created before terminal/background threads. The parent only forwards fixed
// file routes and never shares the broker child's native descriptors.
// Loss of the parent channel permanently stops this
// instance. Reopening the WebUI creates a fresh service and archive sessions.
class FileBroker {
public:
    ~FileBroker();
    bool start(const std::string& special_comm);
    ApiReply handle(const std::string& path, const std::string& body);
    bool isJobActive();
    void shutdown();
private:
    friend struct FileBrokerTestPeer;
    mutable std::mutex mutex_;
    int fd_ = -1;
    pid_t child_ = -1;
};
}


