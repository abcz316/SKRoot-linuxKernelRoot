#pragma once

#include <sys/types.h>

#include <cstdint>
#include <string>
#include <vector>

namespace block_device {

inline constexpr uint32_t kKernelMinorBits = 20;
inline constexpr uint32_t kKernelMinorMask = (1u << kKernelMinorBits) - 1u;

struct DevNodeInfo {
    char name[256] = {0};
    char path[512] = {0};

    dev_t original_rdev = 0;
    uint32_t kernel_rdev = 0;
};

enum class BlockKind {
    Unknown,
    PhysicalDisk,
    PhysicalPartition,
    DeviceMapper,
    MmcBootArea,
    Loop,
    Zram,
    RamDisk,
    MdRaid,
    NetworkBlock,
    Optical,
};

enum class ProtectionMode {
    // 保护恢复出厂无法恢复的启动、固件、校准数据和整盘结构。
    // 默认不保护 userdata/cache/metadata 等运行时数据分区。
    AntiBrick,

    // 更激进：同时保护 userdata/metadata，可能影响恢复出厂、加密维护等功能。
    AntiWipe,
};

struct BuildOptions {
    ProtectionMode mode = ProtectionMode::AntiBrick;

    bool protect_internal_disks = true;
    bool protect_internal_partitions = true;
    bool protect_mmc_boot_areas = true;
    bool protect_system_mappers = true;

    // 无 PARTNAME、无 by-name 的内部真实分区仍默认保护，避免漏掉厂商私有分区。
    bool protect_unnamed_internal_partitions = true;
};

struct ByNameAlias {
    std::string name;
    std::string path;
};

struct BlockDeviceRecord {
    std::string kernel_name;   // sda15 / dm-0 / mmcblk0boot0
    std::string sysfs_path;    // /sys/class/block/sda15
    std::string real_sysfs_path;
    std::string dev_name;      // uevent DEVNAME
    std::string part_name;     // uevent PARTNAME 或 by-name 补充
    std::string dm_name;       // /sys/class/block/<name>/dm/name
    std::string dev_path;      // 可用于 open/stat 的真实节点

    dev_t rdev = 0;
    dev_t parent_rdev = 0;
    uint64_t size_sectors = 0;

    BlockKind kind = BlockKind::Unknown;

    bool removable = false;
    bool read_only = false;
    bool internal = false;
    bool has_partition_file = false;
    bool virtual_device = false;
    bool usb_backed = false;

    std::vector<dev_t> slaves;
    std::vector<ByNameAlias> aliases;
};

uint32_t user_rdev_to_kernel_dev(dev_t rdev);
const char* block_kind_to_string(BlockKind kind);

} // namespace block_device
