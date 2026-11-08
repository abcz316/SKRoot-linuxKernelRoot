# Standalone SUSFS SDK package

This directory contains an optional SKRoot Pro native module skeleton. Its fixed
module ID is `fa362333cf458e832cd032fda9a9f3c6`; the ID is intentionally
different from the PLUS ID and is never generated during a build.

The native entry starts the existing LKM management service with the SDK supplied
`module_private_dir`. The service keeps `config.json`, its control socket and
loader state below that directory. The entry does not discover or contact a PLUS
module. The WebUI only forwards the current `/api/susfs/*` routes to that
private-directory service; static assets are packaged from the maintained
standalone `webroot/` tree.

Build on Windows with the installed NDK and SDK:

```powershell
./build-native.ps1 -OutputDirectory ../../build/susfs-standalone
python ./package_standalone.py `
  --build-dir ../../build/susfs-standalone `
  --lkm-dir ../../build/plus-lkm-sequential/lkm `
  --out ../../release/current/susfs-standalone/0.3.11-6.6-6.12-文件系统隐藏SUSFS-SCS兼容-arm64.zip
```

The package is an SDK development artifact. It is not the PLUS installation
package and does not change the single-package PLUS delivery. Build output is
bound to the fixed identity, native SHA-256 and file list before packaging;
missing or stale LKM assets are rejected.

Uninstall stops only the module-private management service. It does not issue
`rmmod`: the loader may share a kernel module or encounter a built-in SUSFS, so
the normal upstream unload boundary remains reboot or a separately verified
loader operation.

6.6 适配候选与 6.12 共用同一用户态程序和安装包，加载器根据运行内核 release 及现有 KMI 清单自动选择。6.6 保留名称匹配、作用组和 manager FD 等 SKP 扩展，按已核验的目录回调组合保留 SKP 目录保护链；只读内容替换暂不开放，内核返回明确能力原因，WebUI 将该选项标记为“6.6 暂不可用”并置灰。导入或编辑旧内容规则不会自动降级成路径模式。本次仅构建和主机验证新增适配，未重复验证上游基础功能或 SKP SDK，也未进行 6.6 设备效果测试。

“不保留后台”具有启动保护：页面加载完成后连续在前台保持 3 秒才启用失焦和后台退出；启动广告或浏览器过渡产生失焦/隐藏时重新计时。该保护不会因心跳或配置刷新重复延长，启用后继续严格执行失焦/切后台退出；真实 pagehide 在保护期内也会退出。单次心跳网络失败改为重试，约 20 秒失联回收保持。没有为特定浏览器、广告或 SDK 增加特殊豁免。

首次配置由 management/default_config.hpp 内置，在私有目录尚无 susfs/config.json 时保存后自动应用，默认开启“不保留后台”。已有配置及用户清空后保存的配置保持原值；默认规则不锁定、不在启动时补回。配置先于服务就绪建立，随后沿用现有加载、包清单等待及规则恢复流程；损坏的已有配置保留并报告错误。

0.3.5 新增路径隐藏的“隐藏文件夹内容”开关。新建目录规则默认开启，保留目录入口，只隐藏内部子项；三个内置默认目录同样启用此选项，普通文件和已有用户规则保持原语义。新模式需要更新后的 6.6/6.12 LKM，更新安装包后需重启以加载新内核模块。

0.3.6 合入本轮选定上游修复：探针关闭后重新启用、隐藏目录占位信息清理、全局能力与初始化状态一致、符号隐藏误报修正。升级后需重启加载新 LKM；规则、内置目录内容隐藏默认项和后台偏好延续现有配置。

0.3.7 将选项名称统一为“仅隐藏文件夹内容”，界面说明为“放行使文件夹本身可见，不适用于单个文件目标”。规则字段和应用行为保持。

0.3.8 将“仅隐藏文件夹内容”改为基础目录权限检查，解除其对重定向、只读快照和新增符号链接钩子的初始化依赖；目录列表仍由原 getdents 路径过滤。目录本身保留可见、打开和进入能力，作用域内子路径搜索被拒绝；在其中创建新项也受限，生效前已持有的内部目录句柄仍有边界。

0.3.9 修复 FUSE 等后置过滤路径的内容隐藏空目录结果：当匹配“仅隐藏文件夹内容”且整批没有可见项时，清零原始结果并返回 EOF，不再生成可能被文件管理器解析为目录自身的空名称占位项。清零失败返回 EFAULT；普通选择性隐藏仍保留最小占位以继续枚举后续可见项，原 getdents/SKP 链保持。覆盖 native、compat、点目录、后续批次和缓冲区故障的主机回归；主机验证不等于 Android FUSE 实机验证。更新安装包后需重启加载新 LKM。

0.3.10 补全普通路径隐藏的空目录修复：仅隐藏子目录 ab 时，删除同级最后一个可见文件后，旧版会返回空名称记录并可能显示父目录自身。所有后过滤的全隐藏批次现在均清零并内部续读，直到找到可见条目或原系统调用返回真正的 EOF/错误，不再产生占位项。每批保留原始参数、重新获取目录 FD 并经过原 SKP 调用链；长列表可调度、可被信号中断。主机回归覆盖删除前后、下一批可见项、native/compat、FD 替换、原始参数和缓冲区错误；未宣称 Android FUSE 实机效果已验证。

0.3.11 接纳启用影子调用栈且未启用内核 BTI 时的标准 SCS 函数入口，同时覆盖编译器直接生成和加载时由 PAC 转换的形式，不限定内核小版本。目录过滤继续保留原系统调用及现有钩子；目录组合资格不足时使用后过滤。0.3.10 的全隐藏批次清零和继续读取行为保持。
