#pragma once
#include <string>
#include <string_view>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <fstream>
#include <sstream>
#include <cctype>

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

} // namespace android_pkgmap