# 安卓离线阅读器

应用名称：SUSFS 使用手册。包名 org.susfs4skp.guide，当前应用版本 0.4.2 / versionCode 5，手册内容对应 SUSFS 0.3.0，与 SUSFS 模块包分别安装和更新。要求 Android 8.0 及以上，使用系统 WebView。

这是项目使用文档的阅读载体，不是第三个 SKP 模块，不连接 SUSFS/PLUS 的私有服务，不读取设备应用或规则。

## 手机操作

- 安装 APK 后直接打开，断网也可完成交互教程和阅读完整参考手册。
- 交互教程在打包的真实 WebUI 上使用虚构数据练习，不会连接或配置真实 SUSFS 模块，也不会访问用户文件。
- 在课程中按步骤操作，参考文档保留全部图示和参数解释；返回键先交给当前课程或文档处理，再返回上一页或退出。
- 首页右上角设置中可调整阅读字号；图文参考内保留 Aa，可打印或另存 PDF、返回学习首页。
- 打印会先打开完整参考手册，再等待图片和说明准备完成，避免只打印交互课程的外框；打印后可用返回键或 Aa 中“返回封面”回到学习首页。
- 本机保存已完成课程、阅读偏好和参考文档阅读位置；进行中的练习在当前会话可继续，完全退出后恢复干净示例。
- 点“保存 SVG”后由系统选择保存位置，只写用户选择的那一个文件。

不申请 Root、联网或广泛存储权限。切后台和系统保存/打印界面不会主动关闭阅读器。

## 本地构建

先在仓库根目录生成当前图示手册，再执行：

    python docs/webui-guide/interactive/build.py
    powershell -NoProfile -ExecutionPolicy Bypass -File docs/webui-guide/android/build-apk.ps1
    node docs/webui-guide/interactive/verify-interactive.cjs
    python docs/webui-guide/android/verify-apk.py ../build/susfs-guide-interactive-042-20261022/susfs-guide-0.4.2.apk --receipt ../build/susfs-guide-interactive-042-20261022/build-receipt.json --source-root docs/webui-guide/android --webui-source-root module/webroot --report ../work/susfs-interactive-guide-042-20261022/apk-verification.json
    python docs/webui-guide/android/test-local-assets.py ../build/susfs-guide-interactive-042-20261022/susfs-guide-0.4.2.apk --output ../work/susfs-interactive-guide-042-20261022/native-routes

仅使用本机 JDK 17 和 Android SDK，无 Gradle 或网络依赖。interactive/build.py 生成课程入口、模拟响应和完整真实 webroot，把原图示手册放入 reference/；原离线 HTML 仍可独立分享。

默认输出在工作区 build/susfs-guide-interactive-042-20261022/。正式交付为 release/current/SUSFS互动手册-0.4.2.apk，保留签名验证和 SHA-256 记录。app-perspective.js/css 必须同时打包，参与全部资产哈希校验。

签名材料只保存在工作区 build/signing/susfs-guide-android/，不能提交或打包分享；后续更新同包名应用需要继续使用这份签名。

## 校验范围

verify-apk.py 核对应用身份、SDK、无权限/原生库/后台服务、v2/v3 签名、所有本地资产和原生源码哈希，并按元数据的双映射核对生产 webroot 源文件与 APK 文件。test-local-assets.py 提取生产 Java 方法，在主机 Java 中对 APK 真实条目检查路径、字节、MIME、文本编码和失败情况；字体等当前未打包格式另用明确标记的合成资源覆盖。打印路由、一次性标记、等待就绪、过期回调、封面返回及 iframe 联合历史的处理使用 WebView/PrintManager 测试替身检查，不代表系统打印或设备返回手势已实测。

原生只允许读取打包的本地手册资源，拒绝外部网页和文件 URL。实体 Android WebView、系统保存窗口和打印服务的交互需在设备上确认，主机浏览器验证不等于真机测试。

2026-10-22：阅读器 0.4.0 支持交互教程、完整本地 WebUI 资源路由和 reference 教学图导出。资产改为 ZIP API 使用正斜杠追加，签名前和最终校验都检查原始条目名；生产 webroot 源文件和 APK 字节均由双哈希清单覆盖。旧版相同签名可覆盖升级，无须清除阅读数据。
