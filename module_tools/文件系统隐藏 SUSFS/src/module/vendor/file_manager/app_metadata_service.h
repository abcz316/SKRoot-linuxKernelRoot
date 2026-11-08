#pragma once

#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace app_metadata {

struct Reply { int status = 200; std::string body; };
struct ProcessResult { bool success = false; std::string output; };

// Anonymous stdin/stdout only; no shell, endpoint, inherited server descriptors,
// or credentials are exposed to the helper. Also used by host process tests.
ProcessResult runProcess(const std::string& executable, const std::vector<std::string>& arguments,
                         const std::vector<std::string>& environment, const std::string& input,
                         std::chrono::milliseconds timeout, std::size_t max_output);

// Normalize an SDK-extracted, root-owned module resource before ART loads it.
// Identity checks precede chmod; a second fstat confirms the read-only result.
bool prepareDexResource(const std::string& path);

class Service {
public:
    using Runner = std::function<ProcessResult(const std::string&)>;
    explicit Service(Runner runner = {});
    void configure(const std::string& dex_path, std::function<bool()> initialize = {});
    Reply handle(const std::string& body);
    bool active() const;
private:
    struct Entry { std::string package, label, icon, status, version; int uid = -1; };
    struct Flight;
    ProcessResult run(const std::string& input);
    std::string m_dex_path;
    std::function<bool()> m_initialize;
    Runner m_runner;
    mutable std::mutex m_mutex;
    std::map<std::string, Entry> m_cache;
    std::map<std::string, std::shared_ptr<Flight>> m_flights;
};

} // namespace app_metadata
