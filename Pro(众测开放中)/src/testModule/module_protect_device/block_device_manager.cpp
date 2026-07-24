#include "block_device_manager.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <map>

namespace block_device {

uint32_t user_rdev_to_kernel_dev(dev_t rdev) {
    const uint32_t maj = static_cast<uint32_t>(major(rdev));
    const uint32_t min = static_cast<uint32_t>(minor(rdev));
    return (maj << kKernelMinorBits) | (min & kKernelMinorMask);
}

const char* block_kind_to_string(BlockKind kind) {
    switch (kind) {
        case BlockKind::PhysicalDisk: return "physical-disk";
        case BlockKind::PhysicalPartition: return "physical-partition";
        case BlockKind::DeviceMapper: return "device-mapper";
        case BlockKind::MmcBootArea: return "mmc-boot-area";
        case BlockKind::Loop: return "loop";
        case BlockKind::Zram: return "zram";
        case BlockKind::RamDisk: return "ram-disk";
        case BlockKind::MdRaid: return "md-raid";
        case BlockKind::NetworkBlock: return "network-block";
        case BlockKind::Optical: return "optical";
        case BlockKind::Unknown:
        default: return "unknown";
    }
}

DeviceProtectionManager::DeviceProtectionManager(BuildOptions options)
    : options_(options), policy_(options) {}

bool DeviceProtectionManager::build_protected_device_list(
    std::vector<DevNodeInfo>& out_dev_list) {
    out_dev_list.clear();

    std::vector<BlockDeviceRecord> records;
    if (!scanner_.scan(records)) {
        std::printf("device manager: block scan failed\n");
        return false;
    }

    std::map<dev_t, DevNodeInfo> unique_devices;

    for (const auto& record : records) {
        const ProtectionDecision decision = policy_.decide(record);
        const std::string semantic_name = !record.part_name.empty()
            ? record.part_name
            : (!record.dm_name.empty() ? record.dm_name : record.kernel_name);

        std::printf("%c %s name=%s rdev=%u:%u %s\n",
            decision.protect ? '+' : '-',
            record.kernel_name.c_str(),
            semantic_name.empty() ? "-" : semantic_name.c_str(),
            major(record.rdev),
            minor(record.rdev),
            decision.reason.c_str());

        if (!decision.protect) continue;
        unique_devices.emplace(record.rdev, to_dev_node_info(record));
    }

    for (const auto& [rdev, info] : unique_devices) {
        (void)rdev;
        out_dev_list.push_back(info);
    }

    std::printf("device manager: protected %zu unique block devices\n", out_dev_list.size());
    return !out_dev_list.empty();
}

bool DeviceProtectionManager::verify_protected_devices_not_writable(
    const std::vector<DevNodeInfo>& dev_list) const {
    bool ok = true;

    for (const auto& dev : dev_list) {
        if (!dev.path[0]) {
            std::printf("verify protect: no devnode path; hook still covers rdev, "
                        "name=%s rdev=%u:%u\n",
                        dev.name,
                        major(dev.original_rdev), minor(dev.original_rdev));
            continue;
        }

        errno = 0;
        const int fd = ::open(dev.path, O_WRONLY | O_CLOEXEC);
        if (fd >= 0) {
            std::printf("verify protect: FAILED writable open allowed, name=%s path=%s\n",
                        dev.name, dev.path);
            ::close(fd);
            ok = false;
            continue;
        }

        if (errno == EPERM) {
            //std::printf("verify protect: hook denied, name=%s path=%s\n", dev.name, dev.path);
            continue;
        }

        // 某些 eMMC boot area 或只读节点本身会返回 EROFS/EACCES。
        // 这种节点已经不可写，不应导致模块整体启动失败。
        if (errno == EROFS || errno == EACCES || errno == EBUSY) {
            //std::printf("verify protect: already non-writable, name=%s path=%s errno=%d(%s)\n", dev.name, dev.path, errno, std::strerror(errno));
            continue;
        }

        std::printf("verify protect: unexpected error, name=%s path=%s errno=%d(%s)\n", dev.name, dev.path, errno, std::strerror(errno));
        ok = false;
    }

    return ok;
}

DevNodeInfo DeviceProtectionManager::to_dev_node_info(const BlockDeviceRecord& record) {
    DevNodeInfo info {};
    const std::string display_name = !record.part_name.empty()
        ? record.part_name
        : (!record.dm_name.empty() ? record.dm_name : record.kernel_name);

    std::snprintf(info.name, sizeof(info.name), "%s", display_name.c_str());
    if (!record.dev_path.empty()) {
        std::snprintf(info.path, sizeof(info.path), "%s", record.dev_path.c_str());
    }
    info.original_rdev = record.rdev;
    info.kernel_rdev = user_rdev_to_kernel_dev(record.rdev);
    return info;
}

} // namespace block_device
