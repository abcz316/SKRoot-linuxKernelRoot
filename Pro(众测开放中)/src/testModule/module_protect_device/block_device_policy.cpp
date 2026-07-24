#include "block_device_policy.h"

#include <algorithm>
#include <cctype>

namespace block_device {

BlockDevicePolicy::BlockDevicePolicy(BuildOptions options)
    : options_(options) {}

ProtectionDecision BlockDevicePolicy::decide(const BlockDeviceRecord& record) const {
    switch (record.kind) {
        case BlockKind::Loop:
            return {false, "loop-device"};
        case BlockKind::Zram:
            return {false, "zram-device"};
        case BlockKind::RamDisk:
            return {false, "ram-disk"};
        case BlockKind::MdRaid:
            return {false, "md-raid-not-selected"};
        case BlockKind::NetworkBlock:
            return {false, "network-block"};
        case BlockKind::Optical:
            return {false, "optical-device"};
        default:
            break;
    }

    if (!record.internal) {
        return {false, "external-or-unresolved"};
    }

    switch (record.kind) {
        case BlockKind::MmcBootArea:
            return options_.protect_mmc_boot_areas
                ? ProtectionDecision{true, "internal-emmc-boot-area"}
                : ProtectionDecision{false, "mmc-boot-disabled"};

        case BlockKind::PhysicalDisk:
            return options_.protect_internal_disks
                ? ProtectionDecision{true, "internal-physical-disk"}
                : ProtectionDecision{false, "physical-disk-disabled"};

        case BlockKind::PhysicalPartition: {
            if (!options_.protect_internal_partitions) {
                return {false, "physical-partition-disabled"};
            }

            const std::string name = normalize_name(record.part_name);
            if (name.empty() && !options_.protect_unnamed_internal_partitions) {
                return {false, "unnamed-partition-disabled"};
            }

            if (is_ignored_dump_partition(name)) {
                return {false, "dump-or-log-partition"};
            }

            if (options_.mode == ProtectionMode::AntiBrick &&
                is_runtime_mutable_partition(name)) {
                return {false, "runtime-mutable-partition"};
            }

            return {true, name.empty()
                ? "unnamed-internal-partition"
                : "internal-physical-partition"};
        }

        case BlockKind::DeviceMapper:
            if (!options_.protect_system_mappers) {
                return {false, "mapper-protection-disabled"};
            }
            return should_protect_mapper(record.dm_name)
                ? ProtectionDecision{true, "system-device-mapper"}
                : ProtectionDecision{false, "data-or-temporary-mapper"};

        case BlockKind::Unknown:
        default:
            return {false, "unknown-block-kind"};
    }
}

std::string BlockDevicePolicy::normalize_name(const std::string& name) {
    std::string value = name;
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });

    if (value.size() > 2 && value[value.size() - 2] == '_' &&
        (value.back() == 'a' || value.back() == 'b')) {
        value.resize(value.size() - 2);
    }
    return value;
}

bool BlockDevicePolicy::is_runtime_mutable_partition(const std::string& name) {
    return name == "userdata" ||
           name == "cache" ||
           name == "metadata";
}

bool BlockDevicePolicy::is_ignored_dump_partition(const std::string& name) {
    return name == "logfs" ||
           name == "logdump" ||
           name == "rawdump" ||
           name == "ramdump" ||
           name == "xbl_sc_logs" ||
           name == "qmcs" ||
           name.rfind("xbl_ramdump_", 0) == 0;
}

bool BlockDevicePolicy::should_protect_mapper(const std::string& dm_name) {
    std::string value = normalize_name(dm_name);
    if (value.empty()) return false;

    if (value.find("cow") != std::string::npos ||
        value.find("snapshot") != std::string::npos ||
        value.find("scratch") != std::string::npos ||
        value.find("userdata") != std::string::npos ||
        value.find("metadata") != std::string::npos ||
        value.find("default-key") != std::string::npos ||
        value == "user") {
        return false;
    }

    if (value.rfind("my_", 0) == 0) return true;

    return value == "system" ||
           value == "system_ext" ||
           value == "vendor" ||
           value == "product" ||
           value == "odm" ||
           value == "vendor_dlkm" ||
           value == "odm_dlkm" ||
           value == "system_dlkm";
}

} // namespace block_device
