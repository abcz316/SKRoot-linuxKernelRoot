#pragma once

#include "block_device_types.h"

#include <string>

namespace block_device {

struct ProtectionDecision {
    bool protect = false;
    std::string reason;
};

class BlockDevicePolicy {
public:
    explicit BlockDevicePolicy(BuildOptions options = {});

    ProtectionDecision decide(const BlockDeviceRecord& record) const;

private:
    BuildOptions options_;

    static std::string normalize_name(const std::string& name);
    static bool is_runtime_mutable_partition(const std::string& name);
    static bool is_ignored_dump_partition(const std::string& name);
    static bool should_protect_mapper(const std::string& dm_name);
};

} // namespace block_device
