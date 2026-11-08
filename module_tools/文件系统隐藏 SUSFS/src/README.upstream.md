[English](README.en.md)

# susfs4ksu-lkm

SUSFS 的**可加载内核模块（LKM）移植版**：让 susfs 可以在不用重编译内核的情况下运行 。

## 加载

`.ko` 要选与设备内核对应的那一份，例如 5.15 设备用 `susfs_guard_lkm-android13-5.15.ko`。

**KernelSU 设备**：

```sh
ksud insmod /data/adb/loader/susfs_guard_lkm.ko
```

**非 KernelSU 设备**：用 release 附带的加载器 `susfs_insmod`：

```sh
susfs_insmod /data/adb/loader/susfs_guard_lkm.ko
```

卸载：

```sh
rmmod susfs_guard_lkm
```

## 作为 KernelSU 模块刷入

想免去手动选 `.ko`，每个 release 还附带打包好的模块 `susfs_guard_lkm-module-<tag>-arm64.zip`：在 KernelSU 管理器里刷入、重启即可。模块会按设备内核（`/proc/sys/kernel/osrelease`）自动选择并加载对应的 `.ko`（带 `expose_proc=1`），只负责加载、不设任何 susfs 规则；若系统已存在 susfs 则跳过。仅 arm64、仅 KernelSU 系管理器。`expose_proc=1` 会建立 `/proc/susfs_*` 控制节点，sus 规则通过这些节点下发。要移除：在管理器里停用或删除本模块（重启后生效），或 `rmmod susfs_guard_lkm` 当场卸载。

默认在模块的 `post-fs-data` 阶段加载。若需提前到公共 `post-fs-data.d` 阶段，以 root 执行：

```sh
touch /data/adb/modules/susfs_guard_lkm/early_load
```

重启后生效。删除该文件并重启可恢复默认加载；升级会保留此设置。两个阶段共用加载器，已有 SUSFS 时跳过，并遵守安全模式和模块停用/删除标记。卸载只移除本模块拥有的公共脚本，不会当场卸载正在运行的 LKM。

当 SUSFS 规则或原始 kstat 快照必须在模块 post-fs-data 脚本和挂载之前配置时，请启用提前加载。这样可以及时提供 SUSFS 接口，让这些操作在所需的启动阶段执行。如果管理器在公共脚本之前应用 SUSFS 设置，仍需更早的加载阶段。模块只负责加载 LKM，设置由管理器应用。

## 接口文档

全部 `/proc` 控制节点，见 **[PROC_INTERFACES.md](PROC_INTERFACES.md)**。

## License

GPL-2.0，见 [LICENSE](LICENSE)。移植来源：[susfs4ksu](https://gitlab.com/simonpunk/susfs4ksu)（功能逻辑与 hook 点）、
[SukiSU-Ultra](https://github.com/SukiSU-Ultra/SukiSU-Ultra)（`patch_memory` / `lsm_hook` / `symbol_resolver`）。

## 免责声明

仅用于技术研究与学习。在自担风险的前提下使用。
