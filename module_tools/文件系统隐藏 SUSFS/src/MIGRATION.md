# SUSFS LKM migration notes

本地实现已经从旧的整批事务迁移到独立 SUSFS 模块的逐条管理模型。当前固定基线是 upstream main `6753d9c189b058a5978eddd7d2093f95b5be68a2`，详见 [UPSTREAM.json](UPSTREAM.json)。

## 当前 ABI

`kernel/skp_sequential.h` 定义 `CLEAR_FAMILY`、`ADD_RULE` 和 `REGISTER_MANAGER`。每条规则包含 family、profile、主体 selector、路径/目标和 kstat 值。管理服务按 path → kstat → map → redirect → mount 清理后逐条添加；清理失败跳过本族重建，添加失败记录 errno 后继续，控制通道失效后剩余步骤为 `not_executed`。

内核保留并发安全的锁、RCU、inode/path 引用、kprobe 注销、readlink wrapper 恢复和 task-work 回调排空。规则删除后不会让旧读者访问已释放对象。管理层没有 revision/CAS、摘要、异步 job、WAL、快照回滚、冲突恢复、补偿、20 秒 owner 失效或永久 pin。

## 配置与模块边界

独立 SUSFS 模块私有目录仅保存当前 JSON，临时文件写入后 rename。重启重新读取并应用；旧独立配置和 PLUS 内嵌配置不迁移，首次配置为空。常驻服务使用受权限保护的本地 socket；文件代理子进程直接通过 proc 节点登记 manager FD。PLUS 不再连接该服务，也不包含 SUSFS API、管理 client 或 LKM。

## 验收边界

主机测试和 DDK 编译证据见 `work/plus-lkm-embedded-20261018/` 与 `build/plus-lkm-sequential/`。当前设备组合尚未重新安装本候选包；设备应用拦截只允许自编 Probe 或 Maple 检测。上游未声明的能力维持原语义，FD `172→169` 暂缓。

旧事务协议、旧管理端和旧快照实现已经从活跃源码删除；历史设计和证据保存在工作区归档中。
