#pragma once

#include "block_device_types.h"

#include <map>
#include <set>
#include <string>
#include <vector>

namespace block_device {

class BlockDeviceScanner {
public:
    bool scan(std::vector<BlockDeviceRecord>& out_records);

private:
    using UeventMap = std::map<std::string, std::string>;
    using AliasMap = std::map<dev_t, std::vector<ByNameAlias>>;

    bool collect_sysfs_records(std::vector<BlockDeviceRecord>& records);
    bool collect_by_name_aliases(AliasMap& aliases);
    void attach_aliases(const AliasMap& aliases, std::vector<BlockDeviceRecord>& records);
    void classify_records(std::vector<BlockDeviceRecord>& records);
    void resolve_internal_storage(std::vector<BlockDeviceRecord>& records);

    static bool read_text_file(const std::string& path, std::string& out);
    static bool read_uint64_file(const std::string& path, uint64_t& out);
    static bool read_bool_file(const std::string& path, bool& out);
    static bool read_sysfs_dev(const std::string& path, dev_t& out);
    static bool parse_uevent(const std::string& path, UeventMap& out);
    static bool path_exists(const std::string& path);
    static std::string real_path(const std::string& path);
    static std::string basename_of(const std::string& path);

    static bool is_exact_numeric_suffix(const std::string& value, const std::string& prefix);
    static bool is_mmc_boot_name(const std::string& name);
    static bool is_virtual_block_path(const std::string& real_sysfs_path);
    static bool ancestor_has_subsystem(const std::string& real_sysfs_path,
                                       const std::string& subsystem_name);

    static bool find_parent_disk_rdev(const BlockDeviceRecord& record, dev_t& out_parent);
    static bool locate_devnode(const BlockDeviceRecord& record, std::string& out_path);
    static bool locate_devnode_by_rdev(dev_t target, std::string& out_path);

    static std::vector<std::string> discover_by_name_dirs();
    static void add_by_name_dir_if_exists(const std::string& path,
                                          std::set<std::string>& paths);

    static std::set<dev_t> collect_mount_anchor_rdevs();
    static bool is_internal_mount_point(const std::string& mount_point);
    static bool parse_major_minor(const std::string& value, dev_t& out);

    static BlockDeviceRecord* find_record(std::vector<BlockDeviceRecord>& records, dev_t rdev);
    static const BlockDeviceRecord* find_record(const std::vector<BlockDeviceRecord>& records,
                                                dev_t rdev);
    static void collect_root_disks(const std::vector<BlockDeviceRecord>& records,
                                   dev_t rdev,
                                   std::set<dev_t>& visited,
                                   std::set<dev_t>& out_disks);
    static std::string normalized_partition_name(const std::string& name);
    static bool is_internal_anchor_name(const std::string& name);
};

} // namespace block_device
