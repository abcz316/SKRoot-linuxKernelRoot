#include "block_device_scanner.h"

#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace block_device {
namespace fs = std::filesystem;

namespace {

bool is_dot_entry(const char* name) {
    return !name || std::strcmp(name, ".") == 0 || std::strcmp(name, "..") == 0;
}

std::string trim_line(std::string value) {
    while (!value.empty() && (value.back() == '\n' || value.back() == '\r' ||
                              value.back() == ' ' || value.back() == '\t')) {
        value.pop_back();
    }
    size_t start = 0;
    while (start < value.size() && (value[start] == ' ' || value[start] == '\t')) {
        ++start;
    }
    return value.substr(start);
}

std::string strip_slot_suffix(std::string value) {
    if (value.size() > 2 && value[value.size() - 2] == '_' &&
        (value.back() == 'a' || value.back() == 'b')) {
        value.resize(value.size() - 2);
    }
    return value;
}

} // namespace

bool BlockDeviceScanner::scan(std::vector<BlockDeviceRecord>& out_records) {
    out_records.clear();

    if (!collect_sysfs_records(out_records)) {
        std::printf("block scan: cannot enumerate /sys/class/block\n");
        return false;
    }

    AliasMap aliases;
    collect_by_name_aliases(aliases);
    attach_aliases(aliases, out_records);
    classify_records(out_records);
    resolve_internal_storage(out_records);

    return !out_records.empty();
}

bool BlockDeviceScanner::collect_sysfs_records(std::vector<BlockDeviceRecord>& records) {
    DIR* dir = ::opendir("/sys/class/block");
    if (!dir) {
        std::printf("block scan: opendir /sys/class/block failed: %d(%s)\n",
                    errno, std::strerror(errno));
        return false;
    }

    struct dirent* ent = nullptr;
    while ((ent = ::readdir(dir)) != nullptr) {
        if (is_dot_entry(ent->d_name)) continue;

        BlockDeviceRecord record;
        record.kernel_name = ent->d_name;
        record.sysfs_path = "/sys/class/block/" + record.kernel_name;
        record.real_sysfs_path = real_path(record.sysfs_path);
        if (record.real_sysfs_path.empty()) {
            std::printf("block scan: realpath failed: %s\n", record.sysfs_path.c_str());
            continue;
        }

        if (!read_sysfs_dev(record.sysfs_path + "/dev", record.rdev)) {
            std::printf("block scan: read dev failed: %s\n", record.kernel_name.c_str());
            continue;
        }

        UeventMap uevent;
        parse_uevent(record.sysfs_path + "/uevent", uevent);
        if (const auto it = uevent.find("DEVNAME"); it != uevent.end()) {
            record.dev_name = it->second;
        }
        if (const auto it = uevent.find("PARTNAME"); it != uevent.end()) {
            record.part_name = it->second;
        }

        read_uint64_file(record.sysfs_path + "/size", record.size_sectors);
        read_bool_file(record.sysfs_path + "/removable", record.removable);
        read_bool_file(record.sysfs_path + "/ro", record.read_only);

        record.has_partition_file = path_exists(record.sysfs_path + "/partition");
        if (const auto it = uevent.find("DEVTYPE");
            it != uevent.end() && it->second == "partition") {
            record.has_partition_file = true;
        }
        record.virtual_device = is_virtual_block_path(record.real_sysfs_path);
        record.usb_backed = ancestor_has_subsystem(record.real_sysfs_path, "usb");

        read_text_file(record.sysfs_path + "/dm/name", record.dm_name);
        record.dm_name = trim_line(record.dm_name);

        const std::string slaves_path = record.sysfs_path + "/slaves";
        DIR* slaves_dir = ::opendir(slaves_path.c_str());
        if (slaves_dir) {
            struct dirent* slave = nullptr;
            while ((slave = ::readdir(slaves_dir)) != nullptr) {
                if (is_dot_entry(slave->d_name)) continue;
                dev_t slave_rdev = 0;
                const std::string dev_file = "/sys/class/block/" +
                                             std::string(slave->d_name) + "/dev";
                if (read_sysfs_dev(dev_file, slave_rdev)) {
                    record.slaves.push_back(slave_rdev);
                }
            }
            ::closedir(slaves_dir);
        }

        locate_devnode(record, record.dev_path);
        records.push_back(std::move(record));
    }

    ::closedir(dir);
    return !records.empty();
}

bool BlockDeviceScanner::collect_by_name_aliases(AliasMap& aliases) {
    aliases.clear();

    const std::vector<std::string> dirs = discover_by_name_dirs();
    for (const std::string& dir_path : dirs) {
        DIR* dir = ::opendir(dir_path.c_str());
        if (!dir) continue;

        struct dirent* ent = nullptr;
        while ((ent = ::readdir(dir)) != nullptr) {
            if (is_dot_entry(ent->d_name)) continue;

            const std::string path = dir_path + "/" + ent->d_name;
            struct stat st {};
            if (::stat(path.c_str(), &st) != 0 || !S_ISBLK(st.st_mode)) {
                continue;
            }

            ByNameAlias alias;
            alias.name = ent->d_name;
            alias.path = path;

            auto& values = aliases[st.st_rdev];
            const bool duplicate = std::any_of(values.begin(), values.end(),
                [&](const ByNameAlias& existing) {
                    return existing.name == alias.name && existing.path == alias.path;
                });
            if (!duplicate) values.push_back(std::move(alias));
        }

        ::closedir(dir);
    }

    return !aliases.empty();
}

void BlockDeviceScanner::attach_aliases(const AliasMap& aliases,
                                        std::vector<BlockDeviceRecord>& records) {
    for (auto& record : records) {
        const auto it = aliases.find(record.rdev);
        if (it == aliases.end()) continue;

        record.aliases = it->second;
        if (record.part_name.empty() && !record.aliases.empty()) {
            // 优先选择最短名称，通常比平台目录中的重复别名更干净。
            const auto best = std::min_element(record.aliases.begin(), record.aliases.end(),
                [](const ByNameAlias& left, const ByNameAlias& right) {
                    return left.name.size() < right.name.size();
                });
            record.part_name = best->name;
        }

        if (record.dev_path.empty() && !record.aliases.empty()) {
            record.dev_path = record.aliases.front().path;
        }
    }
}

void BlockDeviceScanner::classify_records(std::vector<BlockDeviceRecord>& records) {
    for (auto& record : records) {
        const std::string& name = record.kernel_name;

        if (path_exists(record.sysfs_path + "/loop") ||
            is_exact_numeric_suffix(name, "loop")) {
            record.kind = BlockKind::Loop;
        } else if (is_exact_numeric_suffix(name, "zram") ||
                   path_exists(record.sysfs_path + "/comp_algorithm")) {
            record.kind = BlockKind::Zram;
        } else if (is_exact_numeric_suffix(name, "ram")) {
            record.kind = BlockKind::RamDisk;
        } else if (is_mmc_boot_name(name)) {
            record.kind = BlockKind::MmcBootArea;
        } else if (!record.dm_name.empty() || path_exists(record.sysfs_path + "/dm")) {
            record.kind = BlockKind::DeviceMapper;
        } else if (record.has_partition_file) {
            record.kind = BlockKind::PhysicalPartition;
        } else if (path_exists(record.sysfs_path + "/md") ||
                   is_exact_numeric_suffix(name, "md")) {
            record.kind = BlockKind::MdRaid;
        } else if (is_exact_numeric_suffix(name, "nbd")) {
            record.kind = BlockKind::NetworkBlock;
        } else if (is_exact_numeric_suffix(name, "sr")) {
            record.kind = BlockKind::Optical;
        } else if (!record.virtual_device && record.size_sectors != 0) {
            record.kind = BlockKind::PhysicalDisk;
        } else {
            record.kind = BlockKind::Unknown;
        }
    }

    for (auto& record : records) {
        if (record.kind == BlockKind::PhysicalPartition) {
            find_parent_disk_rdev(record, record.parent_rdev);
            continue;
        }

        if (record.kind == BlockKind::MmcBootArea) {
            const size_t boot_pos = record.kernel_name.rfind("boot");
            if (boot_pos != std::string::npos) {
                const std::string parent_name = record.kernel_name.substr(0, boot_pos);
                const auto it = std::find_if(records.begin(), records.end(),
                    [&](const BlockDeviceRecord& candidate) {
                        return candidate.kernel_name == parent_name;
                    });
                if (it != records.end()) record.parent_rdev = it->rdev;
            }
        }
    }
}

void BlockDeviceScanner::resolve_internal_storage(std::vector<BlockDeviceRecord>& records) {
    std::set<dev_t> internal_disks;

    // 1. 当前系统核心挂载点是最强的内部存储锚点。
    for (dev_t anchor : collect_mount_anchor_rdevs()) {
        std::set<dev_t> visited;
        collect_root_disks(records, anchor, visited, internal_disks);
    }

    // 2. 已知 Android 固件分区名作为补充锚点。
    for (const auto& record : records) {
        const std::string semantic_name = !record.part_name.empty()
            ? record.part_name
            : record.dm_name;
        if (!is_internal_anchor_name(semantic_name)) continue;

        std::set<dev_t> visited;
        collect_root_disks(records, record.rdev, visited, internal_disks);
    }

    // 3. 对未被锚点覆盖的真实物理盘使用保守 fallback。
    // USB 父链和 removable 设备始终排除；非 virtual 的固定盘通常是 UFS/eMMC LUN。
    for (const auto& record : records) {
        if (record.kind != BlockKind::PhysicalDisk) continue;
        if (record.usb_backed || record.removable || record.virtual_device) continue;
        internal_disks.insert(record.rdev);
    }

    for (auto& record : records) {
        std::set<dev_t> roots;
        std::set<dev_t> visited;
        collect_root_disks(records, record.rdev, visited, roots);

        if (roots.empty()) {
            const std::string semantic_name = !record.part_name.empty()
                ? record.part_name
                : record.dm_name;
            record.internal = !record.usb_backed && !record.removable &&
                              is_internal_anchor_name(semantic_name);
            continue;
        }

        bool all_internal = true;
        for (dev_t root : roots) {
            if (internal_disks.find(root) == internal_disks.end()) {
                all_internal = false;
                break;
            }
        }
        record.internal = all_internal;
    }
}

bool BlockDeviceScanner::read_text_file(const std::string& path, std::string& out) {
    out.clear();
    std::ifstream file(path);
    if (!file.is_open()) return false;

    std::ostringstream stream;
    stream << file.rdbuf();
    out = trim_line(stream.str());
    return true;
}

bool BlockDeviceScanner::read_uint64_file(const std::string& path, uint64_t& out) {
    out = 0;
    std::string value;
    if (!read_text_file(path, value) || value.empty()) return false;

    char* end = nullptr;
    errno = 0;
    const unsigned long long parsed = std::strtoull(value.c_str(), &end, 10);
    if (errno != 0 || end == value.c_str()) return false;

    out = static_cast<uint64_t>(parsed);
    return true;
}

bool BlockDeviceScanner::read_bool_file(const std::string& path, bool& out) {
    uint64_t value = 0;
    if (!read_uint64_file(path, value)) return false;
    out = value != 0;
    return true;
}

bool BlockDeviceScanner::read_sysfs_dev(const std::string& path, dev_t& out) {
    std::string value;
    if (!read_text_file(path, value)) return false;
    return parse_major_minor(value, out);
}

bool BlockDeviceScanner::parse_uevent(const std::string& path, UeventMap& out) {
    out.clear();
    std::ifstream file(path);
    if (!file.is_open()) return false;

    std::string line;
    while (std::getline(file, line)) {
        const size_t pos = line.find('=');
        if (pos == std::string::npos) continue;
        out[line.substr(0, pos)] = trim_line(line.substr(pos + 1));
    }
    return true;
}

bool BlockDeviceScanner::path_exists(const std::string& path) {
    return ::access(path.c_str(), F_OK) == 0;
}

std::string BlockDeviceScanner::real_path(const std::string& path) {
    char resolved[PATH_MAX] = {0};
    if (!::realpath(path.c_str(), resolved)) return {};
    return resolved;
}

std::string BlockDeviceScanner::basename_of(const std::string& path) {
    if (path.empty()) return {};
    const size_t pos = path.find_last_of('/');
    return pos == std::string::npos ? path : path.substr(pos + 1);
}

bool BlockDeviceScanner::is_exact_numeric_suffix(const std::string& value,
                                                  const std::string& prefix) {
    if (value.size() <= prefix.size() || value.compare(0, prefix.size(), prefix) != 0) {
        return false;
    }
    return std::all_of(value.begin() + static_cast<std::ptrdiff_t>(prefix.size()),
                       value.end(),
                       [](unsigned char ch) { return std::isdigit(ch) != 0; });
}

bool BlockDeviceScanner::is_mmc_boot_name(const std::string& name) {
    if (name.rfind("mmcblk", 0) != 0) return false;
    const size_t boot_pos = name.rfind("boot");
    if (boot_pos == std::string::npos || boot_pos <= 6) return false;
    if (name.size() != boot_pos + 5) return false;
    if (name.back() != '0' && name.back() != '1') return false;

    return std::all_of(name.begin() + 6,
                       name.begin() + static_cast<std::ptrdiff_t>(boot_pos),
                       [](unsigned char ch) { return std::isdigit(ch) != 0; });
}

bool BlockDeviceScanner::is_virtual_block_path(const std::string& path) {
    return path.find("/devices/virtual/block/") != std::string::npos;
}

bool BlockDeviceScanner::ancestor_has_subsystem(const std::string& real_sysfs_path,
                                                const std::string& subsystem_name) {
    fs::path current(real_sysfs_path);
    std::error_code ec;

    while (!current.empty() && current != current.root_path()) {
        const fs::path subsystem = current / "subsystem";
        if (fs::exists(subsystem, ec)) {
            const fs::path target = fs::read_symlink(subsystem, ec);
            if (!ec && target.filename() == subsystem_name) return true;
            ec.clear();
        }
        current = current.parent_path();
    }
    return false;
}

bool BlockDeviceScanner::find_parent_disk_rdev(const BlockDeviceRecord& record,
                                               dev_t& out_parent) {
    if (!record.has_partition_file || record.real_sysfs_path.empty()) return false;
    const fs::path parent = fs::path(record.real_sysfs_path).parent_path();
    return read_sysfs_dev((parent / "dev").string(), out_parent);
}

bool BlockDeviceScanner::locate_devnode(const BlockDeviceRecord& record,
                                        std::string& out_path) {
    out_path.clear();
    std::vector<std::string> candidates;

    if (!record.dev_name.empty()) {
        std::string dev_name = record.dev_name;
        if (dev_name.rfind("block/", 0) == 0) dev_name.erase(0, 6);
        candidates.push_back("/dev/block/" + dev_name);
        candidates.push_back("/dev/" + dev_name);
    }
    candidates.push_back("/dev/block/" + record.kernel_name);

    for (const std::string& path : candidates) {
        struct stat st {};
        if (::stat(path.c_str(), &st) == 0 && S_ISBLK(st.st_mode) &&
            st.st_rdev == record.rdev) {
            out_path = path;
            return true;
        }
    }

    return locate_devnode_by_rdev(record.rdev, out_path);
}

bool BlockDeviceScanner::locate_devnode_by_rdev(dev_t target, std::string& out_path) {
    out_path.clear();
    std::error_code ec;
    fs::recursive_directory_iterator it(
        "/dev/block",
        fs::directory_options::skip_permission_denied,
        ec);
    const fs::recursive_directory_iterator end;

    for (; !ec && it != end; it.increment(ec)) {
        if (it.depth() > 6) {
            it.disable_recursion_pending();
            continue;
        }

        const fs::path path = it->path();
        struct stat st {};
        if (::stat(path.c_str(), &st) == 0 && S_ISBLK(st.st_mode) &&
            st.st_rdev == target) {
            out_path = path.string();
            return true;
        }
    }
    return false;
}

std::vector<std::string> BlockDeviceScanner::discover_by_name_dirs() {
    std::set<std::string> paths;
    add_by_name_dir_if_exists("/dev/block/by-name", paths);
    add_by_name_dir_if_exists("/dev/block/bootdevice/by-name", paths);
    add_by_name_dir_if_exists("/dev/block/platform/bootdevice/by-name", paths);

    std::error_code ec;
    fs::recursive_directory_iterator it(
        "/dev/block/platform",
        fs::directory_options::skip_permission_denied,
        ec);
    const fs::recursive_directory_iterator end;

    for (; !ec && it != end; it.increment(ec)) {
        if (it.depth() > 5) {
            it.disable_recursion_pending();
            continue;
        }
        if (it->path().filename() == "by-name" && it->is_directory(ec)) {
            paths.insert(it->path().string());
        }
    }

    return {paths.begin(), paths.end()};
}

void BlockDeviceScanner::add_by_name_dir_if_exists(const std::string& path,
                                                   std::set<std::string>& paths) {
    struct stat st {};
    if (::stat(path.c_str(), &st) == 0 && S_ISDIR(st.st_mode)) {
        paths.insert(path);
    }
}

std::set<dev_t> BlockDeviceScanner::collect_mount_anchor_rdevs() {
    std::set<dev_t> result;
    std::ifstream file("/proc/self/mountinfo");
    if (!file.is_open()) return result;

    std::string line;
    while (std::getline(file, line)) {
        std::istringstream stream(line);
        std::string mount_id;
        std::string parent_id;
        std::string major_minor;
        std::string root;
        std::string mount_point;
        if (!(stream >> mount_id >> parent_id >> major_minor >> root >> mount_point)) {
            continue;
        }
        if (!is_internal_mount_point(mount_point)) continue;

        dev_t rdev = 0;
        if (parse_major_minor(major_minor, rdev) && (major(rdev) != 0 || minor(rdev) != 0)) {
            result.insert(rdev);
        }
    }
    return result;
}

bool BlockDeviceScanner::is_internal_mount_point(const std::string& mount_point) {
    static const char* kMounts[] = {
        "/", "/system", "/system_ext", "/vendor", "/product", "/odm",
        "/vendor_dlkm", "/odm_dlkm", "/system_dlkm", "/data", "/metadata"
    };
    return std::any_of(std::begin(kMounts), std::end(kMounts),
        [&](const char* value) { return mount_point == value; });
}

bool BlockDeviceScanner::parse_major_minor(const std::string& value, dev_t& out) {
    unsigned int maj = 0;
    unsigned int min = 0;
    if (std::sscanf(value.c_str(), "%u:%u", &maj, &min) != 2) return false;
    out = makedev(maj, min);
    return true;
}

BlockDeviceRecord* BlockDeviceScanner::find_record(std::vector<BlockDeviceRecord>& records,
                                                   dev_t rdev) {
    const auto it = std::find_if(records.begin(), records.end(),
        [&](const BlockDeviceRecord& record) { return record.rdev == rdev; });
    return it == records.end() ? nullptr : &*it;
}

const BlockDeviceRecord* BlockDeviceScanner::find_record(
    const std::vector<BlockDeviceRecord>& records,
    dev_t rdev) {
    const auto it = std::find_if(records.begin(), records.end(),
        [&](const BlockDeviceRecord& record) { return record.rdev == rdev; });
    return it == records.end() ? nullptr : &*it;
}

void BlockDeviceScanner::collect_root_disks(const std::vector<BlockDeviceRecord>& records,
                                            dev_t rdev,
                                            std::set<dev_t>& visited,
                                            std::set<dev_t>& out_disks) {
    if (rdev == 0 || !visited.insert(rdev).second) return;

    const BlockDeviceRecord* record = find_record(records, rdev);
    if (!record) return;

    switch (record->kind) {
        case BlockKind::PhysicalDisk:
            out_disks.insert(record->rdev);
            return;

        case BlockKind::PhysicalPartition:
        case BlockKind::MmcBootArea:
            if (record->parent_rdev != 0) {
                collect_root_disks(records, record->parent_rdev, visited, out_disks);
            }
            return;

        case BlockKind::DeviceMapper:
        case BlockKind::MdRaid:
            for (dev_t slave : record->slaves) {
                collect_root_disks(records, slave, visited, out_disks);
            }
            return;

        default:
            if (record->parent_rdev != 0) {
                collect_root_disks(records, record->parent_rdev, visited, out_disks);
            }
            return;
    }
}

std::string BlockDeviceScanner::normalized_partition_name(const std::string& name) {
    std::string value = strip_slot_suffix(name);
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return value;
}

bool BlockDeviceScanner::is_internal_anchor_name(const std::string& name) {
    const std::string value = normalized_partition_name(name);
    if (value.empty()) return false;

    static const char* kAnchorNames[] = {
        "boot", "init_boot", "vendor_boot", "recovery", "vbmeta", "dtbo",
        "super", "system", "system_ext", "vendor", "product", "odm",
        "vendor_dlkm", "odm_dlkm", "system_dlkm", "userdata", "metadata",
        "xbl", "abl", "lk", "preloader", "persist", "modem", "nvram", "nvdata"
    };

    if (value.rfind("my_", 0) == 0) return true;
    return std::any_of(std::begin(kAnchorNames), std::end(kAnchorNames),
        [&](const char* candidate) { return value == candidate; });
}

} // namespace block_device
