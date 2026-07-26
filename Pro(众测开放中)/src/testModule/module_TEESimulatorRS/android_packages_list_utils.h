#pragma once

#include <atomic>
#include <cerrno>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <functional>
#include <limits>
#include <poll.h>
#include <sstream>
#include <string>
#include <string_view>
#include <sys/inotify.h>
#include <unordered_map>
#include <unordered_set>
#include <unistd.h>
#include <utility>
#include <vector>

namespace android_pkgmap {

namespace detail {
    inline void trim_inplace(std::string& s) {
        auto issp = [](unsigned char c){ return std::isspace(c) != 0; };
        size_t l = 0, r = s.size();
        while (l < r && issp(static_cast<unsigned char>(s[l]))) ++l;
        while (r > l && issp(static_cast<unsigned char>(s[r-1]))) --r;
        if (l == 0 && r == s.size()) return;
        s.assign(s.begin() + static_cast<std::ptrdiff_t>(l),
                 s.begin() + static_cast<std::ptrdiff_t>(r));
    }

    // 解析一行：取前两列 <package> <uid>；可选检测是否包含 "@system"
    inline bool parse_line_pkg_uid(const std::string& line,
                                std::string& out_pkg,
                                uint32_t& out_uid,
                                bool* out_is_system = nullptr) {
        if (out_is_system) *out_is_system = false;

        std::string work = line;
        // 去掉 # 注释
        if (auto pos = work.find('#'); pos != std::string::npos) work.resize(pos);
        trim_inplace(work);
        if (work.empty()) return false;

        std::istringstream iss(work);
        std::string pkg;
        unsigned long uid_ul = 0;
        if (!(iss >> pkg >> uid_ul)) return false;

        out_pkg = std::move(pkg);
        out_uid = static_cast<uint32_t>(uid_ul);

        // 扫描剩余列，判断是否有 "@system"
        if (out_is_system) {
            std::string tok;
            while (iss >> tok) {
                if (tok == "@system") {
                    *out_is_system = true;
                    break;
                }
            }
        }
        return true;
    }

    inline bool split_path(const std::string& path,
                        std::string& out_directory,
                        std::string& out_filename) {
        const std::size_t slash = path.find_last_of('/');

        if (slash == std::string::npos || slash + 1 >= path.size()) {
            return false;
        }

        out_directory = slash == 0 ? "/" : path.substr(0, slash);
        out_filename = path.substr(slash + 1);

        return !out_filename.empty();
    }
}

/**
 * 把给定包名列表映射为UID。未命中置为0。
 * @param pkgs  待查询包名列表
 * @param path  packages.list 路径（默认 /data/system/packages.list）
 * @return  {包名 -> uid} 映射，未命中的值为0。文件打不开也返回全0。
 */
inline std::unordered_map<std::string, uint32_t>
read_pkg_uids_from_packages_list(const std::vector<std::string>& pkgs,
                                 const std::string& path = "/data/system/packages.list")
{
    std::unordered_map<std::string, uint32_t> result;
    result.reserve(pkgs.size());
    for (const auto& p : pkgs) result.emplace(p, 0);  // 先默认0

    std::unordered_set<std::string> targets(pkgs.begin(), pkgs.end());
    if (targets.empty()) return result;

    std::ifstream fin(path);
    if (!fin.is_open()) {
        // 无权限/文件不存在：直接返回默认0
        return result;
    }

    std::string line, pkg;
    uint32_t uid = 0;
    size_t remaining = targets.size();

    while (std::getline(fin, line)) {
        if (!detail::parse_line_pkg_uid(line, pkg, uid)) continue;

        if (auto it = targets.find(pkg); it != targets.end()) {
            result[pkg] = uid;
            targets.erase(it);
            if (--remaining == 0) break; // 都找到了，提前结束
        }
    }
    return result;
}

/**
 * 读取整个 packages.list，返回全量 {包名->uid} 映射。
 * @param path  packages.list 路径
 * @return  若文件不可读，返回空map。
 */
inline std::unordered_map<std::string, uint32_t>
read_all_pkg_uids(const std::string& path = "/data/system/packages.list")
{
    std::unordered_map<std::string, uint32_t> map;
    std::ifstream fin(path);
    if (!fin.is_open()) return map;

    std::string line, pkg;
    uint32_t uid = 0;
    // 若同一包名出现多次，后出现的覆盖前者（通常不会发生）
    while (std::getline(fin, line)) {
        if (detail::parse_line_pkg_uid(line, pkg, uid)) {
            map[pkg] = uid;
        }
    }
    return map;
}

/**
 * 读取整个 packages.list，排除system应用，返回全量 {包名->uid} 映射。
 * @param path  packages.list 路径
 * @return  若文件不可读，返回空map。
 */
inline std::unordered_map<std::string, uint32_t>
read_all_pkg_uids_exclude_system(const std::string& path = "/data/system/packages.list")
{
    std::unordered_map<std::string, uint32_t> map;
    std::ifstream fin(path);
    if (!fin.is_open()) return map;

    std::string line, pkg;
    uint32_t uid = 0;
    bool is_system = false;

    while (std::getline(fin, line)) {
        if (!detail::parse_line_pkg_uid(line, pkg, uid, &is_system)) continue;
        if (is_system) continue;
        map[pkg] = uid;
    }
    return map;
}

/**
 * 查询单个包名对应UID；未命中/文件不可读返回0。
 */
inline uint32_t get_uid_for_package(const std::string& pkg,
                                    const std::string& path = "/data/system/packages.list")
{
    if (pkg.empty()) return 0;
    std::ifstream fin(path);
    if (!fin.is_open()) return 0;

    std::string line, name;
    uint32_t uid = 0;
    while (std::getline(fin, line)) {
        if (!detail::parse_line_pkg_uid(line, name, uid)) continue;
        if (name == pkg) return uid;
    }
    return 0;
}

/**
 * 最小化监听 packages.list 是否发生变化。
 *
 * 这里只负责通知“包列表发生过变化”，不读取文件、不比较内容，
 * 也不区分安装、卸载、更新或 UID 变化。
 *
 * 监听目录而不是直接监听 packages.list，是因为 Android 通常先写
 * 临时文件，再通过 rename 覆盖 packages.list。直接监听文件 inode
 * 在文件被替换后可能失效。
 *
 * 监听事件：
 *   IN_MOVED_TO    临时文件 rename 为 packages.list
 *   IN_CLOSE_WRITE 某些厂商直接写 packages.list 后关闭
 *
 * @param callback       检测到变化时调用
 * @param stop_requested 外部停止标志
 * @param path           packages.list 完整路径
 * @param stop_poll_ms   检查停止标志的最长间隔，默认 500ms
 *
 * @return 正常停止返回 true；初始化或监听失败返回 false。
 */
inline bool watch_packages_list_changed(
        const std::function<void()>& callback,
        const std::atomic_bool& stop_requested,
        const std::string& path = "/data/system/packages.list",
        int stop_poll_ms = 500) {
    if (!callback) {
        return false;
    }

    std::string directory;
    std::string filename;

    if (!detail::split_path(path, directory, filename)) {
        return false;
    }

    const int inotify_fd =
        ::inotify_init1(IN_NONBLOCK | IN_CLOEXEC);

    if (inotify_fd < 0) {
        return false;
    }

    constexpr std::uint32_t kWatchMask =
        IN_MOVED_TO |
        IN_CLOSE_WRITE;

    const int watch_descriptor =
        ::inotify_add_watch(
            inotify_fd,
            directory.c_str(),
            kWatchMask);

    if (watch_descriptor < 0) {
        ::close(inotify_fd);
        return false;
    }

    if (stop_poll_ms < 1) {
        stop_poll_ms = 1;
    }

    pollfd poll_fd{
        .fd = inotify_fd,
        .events = POLLIN,
        .revents = 0,
    };

    alignas(inotify_event) char buffer[4096];
    bool success = true;

    while (!stop_requested.load(std::memory_order_relaxed)) {
        poll_fd.revents = 0;

        const int poll_result =
            ::poll(&poll_fd, 1, stop_poll_ms);

        if (poll_result < 0) {
            if (errno == EINTR) {
                continue;
            }

            success = false;
            break;
        }

        if (poll_result == 0) {
            continue;
        }

        if ((poll_fd.revents &
             (POLLERR | POLLHUP | POLLNVAL)) != 0) {
            success = false;
            break;
        }

        if ((poll_fd.revents & POLLIN) == 0) {
            continue;
        }

        for (;;) {
            const ssize_t bytes_read =
                ::read(inotify_fd, buffer, sizeof(buffer));

            if (bytes_read < 0) {
                if (errno == EINTR) {
                    continue;
                }

                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    break;
                }

                success = false;
                break;
            }

            if (bytes_read == 0) {
                success = false;
                break;
            }

            std::size_t offset = 0;

            while (offset + sizeof(inotify_event) <=
                   static_cast<std::size_t>(bytes_read)) {
                const auto* event =
                    reinterpret_cast<const inotify_event*>(
                        buffer + offset);

                const std::size_t event_size =
                    sizeof(inotify_event) + event->len;

                if (offset + event_size >
                    static_cast<std::size_t>(bytes_read)) {
                    success = false;
                    break;
                }

                bool changed = false;

                if ((event->mask & IN_Q_OVERFLOW) != 0) {
                    changed = true;
                } else if (event->len > 0 &&
                           std::string_view(event->name) == filename &&
                           (event->mask &
                            (IN_MOVED_TO | IN_CLOSE_WRITE)) != 0) {
                    changed = true;
                }

                if (changed) {
                    callback();
                }

                offset += event_size;
            }

            if (!success) {
                break;
            }
        }
    }

    ::inotify_rm_watch(inotify_fd, watch_descriptor);
    ::close(inotify_fd);

    return success;
}
} // namespace android_pkgmap