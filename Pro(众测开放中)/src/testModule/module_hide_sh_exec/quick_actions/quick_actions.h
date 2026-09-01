#pragma once
#include <string>
#include <vector>

// 快捷命令：URL 编码存储，最近使用置后，超限淘汰最旧项。
class QuickActions {
public:
    static constexpr size_t kMaxActions = 10;
    static constexpr size_t kRecordCmdLen = 100;

    // 批量记录命令（自动 URL 编码、去重后移、淘汰超限）
    void add(const std::vector<std::string>& cmd);

    // 读取已存储的快捷命令 JSON（空数据返回 "[]"）
    std::string toJson();
};
