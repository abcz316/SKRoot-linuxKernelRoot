# SUSFS 0.3.0 WebUI 使用手册

当前 Android App 已升级为 0.4.2 互动学习手册：先看功能用途，再在真实 WebUI 中跟随高亮操作；包含 12 课、75 个步骤和用途动画。详细构建与维护见 interactive/README.md，原生打包见 android/README.md。练习完全离线，只使用内存示例，不接入模块运行时，也不改变模块版本。

下方的旧图示手册继续作为 App 内按需查阅的完整参考，详细参数与边界默认折叠。

## 成品

安卓安装包：工作区 release/current/SUSFS互动手册-0.4.2.apk，要求 Android 8.0+；无需 Root 或联网权限，与旧版同签名，可覆盖安装。

工作区 release/current/SUSFS-0.3.0-WebUI使用手册/ 包含：

- index.html：内嵌全部图像，可单独复制、离线打开，支持目录、搜索、原图/标注图放大、SVG 下载和打印。
- svg/：54 张真实前端画面标注图、9 张概念原理图，均自包含，可独立分享。
- png/：63 张 SVG 的兼容预览。
- screenshots/：54 张未经重绘的原始 WebUI 截图。
- 阅读说明.txt 与 manifest.json：使用方式和交付文件哈希。

成品另压缩为同名 ZIP。画面由当前生产前端在 localhost 加载隔离教学数据生成，文件、应用清单和成功/失败状态均为示例，不代表设备效果实测。

## 维护与生成

content/ 下三个 JSON 分别维护规则、作用组/基础流程、文件管理/高级功能。正文为 HTML 片段，figures 引用截图 ID，sources 记录当前实现依据。diagrams/ 保存九张 SVG 原图和可复现生成脚本。build.py 控制章节顺序、样式、自包含 SVG 和 HTML 输出。

在仓库根目录依次运行：

    node docs/webui-guide/capture.cjs
    python docs/webui-guide/build.py
    node docs/webui-guide/verify.cjs
    python docs/webui-guide/package.py

捕获与核验使用项目现有 Playwright 依赖及 Chrome；无需设备。捕获脚本通过真实控件操作，不改生产 DOM 来伪造界面；仅对本机测试页面提供模拟 API 数据。

工作证据位于工作区 work/susfs-webui-guide-20261021/，包含：

- capture/screenshots.json：每张截图的视口、控件定位和实际标注边界。
- capture/capture-report.json：前端源码哈希与本地请求记录。
- semantic-audit.md：正文与实现语义的独立复核。
- coverage.json：全部章节、截图和源码覆盖。
- qa/qa-report.json：四种视口、离线读取、资源解码、搜索、放大、下载与打印核验。

## 内容与版本约定

当前文档对应 0.3.0 / versionCode 5、android15-6.6 与 android16-6.12；6.6 的只读内容替换明确禁用。文档更新时须先核对实际 UI 和管理/内核语义，再重拍受影响画面，不能沿用旧截图修改文字冒充新界面。

仅更新使用文档不推进模块版本。若制作中发现需要改变产品行为，另按项目 AGENTS.md 的功能更新约定处理；不能将产品修复混入文档任务。
