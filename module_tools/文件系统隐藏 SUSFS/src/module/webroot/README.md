# 独立 SUSFS WebUI

此目录包含 LKM 模块的静态页面和完整文件管理前端资产。目录浏览、文本编辑、图片预览、归档浏览和选择器保持独立。SUSFS 控制台提供监控、规则、作用组、高级四页，以监控为默认首屏。

文本编辑器支持读取 procfs/sysfs 的动态内容，不使用 `stat` 报告的长度代替内容长度。这类文件以只读快照分块显示；普通文件仍支持编辑保存及变化冲突检测。

监控采用并排的运行状态、规则状态底图卡片；点击规则卡片进入规则页。原有诊断内容在监控页下方默认折叠。规则与作用组均通过宽幅虚线按钮新建；规则显示路径与图标操作，类型和状态由右下角底图区分。作用组默认折叠，每组可独立设置排除/指定模式、广域排除和包名；应用列表显示图标、名称、包名及删除按钮，超过 5 项可滚动。高级页为 uname、bootconfig/cmdline 兼容字段、模块隐藏、AVC、上游路径门限、日志提供专用配置和教程。

## 宿主接入

宿主需要将 `module/webroot/` 作为 WebUI 根目录，并提供同源的 POST API。默认前缀为 `/api/susfs`，也可以在加载 `susfs.js` 前设置 `window.SUSFS_API_BASE`。页面只使用顺序管理接口：

* `/status`：返回 `service_running`、`kernel.online`、`loader_error` 和 `last_result`。
* `/config-get`：返回 `{config: 配置}`，支持 schema 10–14。
* `/config-save`：接收完整 JSON，先持久化再顺序清理和逐条应用，返回 `saved`、`result`、`config` 和 `steps`。
* `/apps`：应用清单；通过 `/api/apps/metadata` 补充名称和图标。
* `/objects-query`、`/kstat-sample`：查询对象状态和读取文件属性。

接口可以返回当前服务的原始 JSON，也可以返回带 `data` 字段的 WebUI 信封。页面不会调用旧的 `config-patch`、revision/CAS、job、WAL 或轮询任务接口。若宿主启用会话鉴权，页面会复用 `RequestApi.initSession()` 并发送 `X-SKRoot-Session`。

规则编辑器以单个组别作为作用范围，最多保存 8 个组别；默认 `id=0` 组不可删除。`profiles[].subjects` 是 schema 10 的可选字段，用于各组独立策略，需与更新的管理服务一起部署。未提供字段的旧 JSON 保留已有含义，编辑旧组策略后才转为独立策略；自定义路径策略优先于组策略。页面保存时固定使用 `mode=groups` 和 `object_rules_enabled=true`，状态展示依据 `/status` 的实际结果。独立页面移除了终端和模拟执行入口，文件页完整操作依赖宿主提供的 `/api/files/*`。

路径隐藏的新建规则默认勾选“仅隐藏文件夹内容”：目录本身保留，子项及其后代隐藏；取消选项则使用原来的整个路径隐藏。普通文件从文件页选择后仍隐藏文件本身，混合选择按各项类型处理。旧字符串路径保持原来语义，不自动变为内容隐藏。schema 14 使用 `{path, hide_contents:true}` 保存该选项；导入、导出及高级设置保留它。内核未报告 `path_contents_hide` 时拒绝新增内容隐藏，不会降级成隐藏整个目录。手动输入路径时应用阶段校验目录类型。

绿色规则底图表示管理接口报告已应用；黄色表示待应用，红色表示失败，灰色表示状态未确认。主机测试和应用成功不等同于设备应用效果验证。高级功能选择“不设置”只停止后续写入，具体恢复方式见对应教程。

运行 `node susfs4skp-lkm/module/tests/standalone-webui-browser.cjs` 进行本机模拟服务测试，覆盖 360px、390px 和桌面视口、四页导航、作用组、五类规则、包名滚动与移除、目标选择和保存失败保留草稿。截图和报告写入 `work/susfs-webui-refactor-20261018/`。


0.3.8 的 path_contents_mode 为 directory_search。path_contents_disabled_reason 区分基础路径、目录缓冲区、目录 FD 查询及原生 getdents 入口不可用；界面保持“仅隐藏文件夹内容”及用户指定简短说明。此模式不再要求名称匹配或只读内容替换能力同时为真。
