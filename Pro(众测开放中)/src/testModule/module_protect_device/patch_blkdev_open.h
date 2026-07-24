#pragma once
#include <iostream>
#include <set>
#include "patch_base.h"
#include "block_device_types.h"

struct BlkdevOpenPatchOffsets {
    uint32_t file_f_mode = 0;
    uint32_t inode_i_rdev = 0;
};

class PatchBlkdevOpen : public PatchBase {
public:
    PatchBlkdevOpen(const PatchBase& patch_base, uint64_t blkdev_open);
    ~PatchBlkdevOpen();

    KModErr patch_blkdev_open(const std::vector<block_device::DevNodeInfo>& protect_dev,
                              const std::string& test_comm,
                              uint64_t control_kaddr,
                              const BlkdevOpenPatchOffsets& off);
private:
    uint64_t m_blkdev_open = 0;
};
