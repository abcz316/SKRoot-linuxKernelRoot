#pragma once

#include "block_device_policy.h"
#include "block_device_scanner.h"
#include "block_device_types.h"

#include <vector>

namespace block_device {

class DeviceProtectionManager {
public:
    explicit DeviceProtectionManager(BuildOptions options = {});

    bool build_protected_device_list(std::vector<DevNodeInfo>& out_dev_list);
    bool verify_protected_devices_not_writable(const std::vector<DevNodeInfo>& dev_list) const;

private:
    BuildOptions options_;
    BlockDeviceScanner scanner_;
    BlockDevicePolicy policy_;

    static DevNodeInfo to_dev_node_info(const BlockDeviceRecord& record);
};

} // namespace block_device
