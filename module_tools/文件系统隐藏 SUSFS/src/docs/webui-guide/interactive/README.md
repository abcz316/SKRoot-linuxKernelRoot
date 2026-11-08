# SUSFS 互动学习手册

App 0.4.2 / versionCode 5，对应 SUSFS 模块 0.3.0。应用与模块分别更新；本轮不改模块功能和版本。

先用一句话和应用视角动画看懂功能，再进入真实 WebUI 跟着高亮控件配置。动画可以切换配置前后并重播，展示隐藏、属性、重定向、映射和挂载等信息如何呈现在目标应用中。高级限制默认折叠，完整图文资料保留在“参数忘了？随时查”。

## 课程

12 节独立练习、75 个步骤：保存与应用、指定作用组、路径隐藏、完整名称匹配、属性伪装、重定向、撤销规则、映射隐藏、挂载隐藏、uname、配置导出、配置导入。每课都有干净的示例数据，可反复重试，也可切换到自由练习。

目录长按打开菜单；普通文件点击打开菜单。紫色框标出本步控件，真正完成选择、勾选和保存后才前进。组名、完整名称、大小、uname release、导出文件名这 5 个示例输入预填好，用户看清后可轻点任意位置继续；3 个概念提示步骤也采用相同操作。按钮、返回和菜单仍保留各自功能。预填步骤不会主动聚焦文本框，透明点击层防止继续操作穿透到下方控件，连续双击只会确认一步。最终保存内容仍由课程完整校验。

支持减少动画、记住完成的课程、回看用途介绍后继续本次练习。完全退出 App 后只保留学习记录，进行中的演练重新开始。动画使用 SVG 与 CSS 的轻量变换；系统或设置关闭动画后仍能看懂图意。练习内核可在首页设置选择 6.12 或 6.6，后者真实保留只读内容替换的灰色禁用状态。

## 隔离方式

`prepare-simulator.py` 完整复制 `module/webroot`，仅在复制的 `index.html` 首个脚本前加入 `simulator.js`；其他 23 个文件字节不变，生产源码不被改写。适配器在页面内存中响应真实前端的接口请求，示例文件、应用列表、保存和应用结果都属于演练。未知接口和其他网络传输明确拒绝，绝不回退到真实服务。

Android 仍不申请 Root、网络或存储权限。只读本地打包资源，不连接 SUSFS/PLUS 私有服务，也不把演练结果描述为设备拦截测试通过。

## 构建与验证

在仓库根目录运行：

```powershell
python docs/webui-guide/interactive/build.py
node docs/webui-guide/interactive/verify-interactive.cjs
powershell -NoProfile -ExecutionPolicy Bypass -File docs/webui-guide/android/build-apk.ps1
python docs/webui-guide/android/verify-apk.py ../build/susfs-guide-interactive-042-20261022/susfs-guide-0.4.2.apk --receipt ../build/susfs-guide-interactive-042-20261022/build-receipt.json --source-root docs/webui-guide/android --report ../work/susfs-interactive-guide-042-20261022/apk-verification.json
python docs/webui-guide/android/test-local-assets.py ../build/susfs-guide-interactive-042-20261022/susfs-guide-0.4.2.apk --output ../work/susfs-interactive-guide-042-20261022/native-routes
```

`build.py` 默认写入工作区 `build/susfs-guide-interactive-042-20261022/assets/guide/`，可通过 `--output` 指定独立构建目录。图文参考从当前离线手册提取，不包含原生签名材料。

`verify-interactive.cjs` 通过真实点击、输入、选择和长按逐步操作正式前端，读取模拟器状态只作断言，不直接修改配置或标记课程完成。覆盖手机和平板宽度、错操作停步、恢复/重试、减少动画及离线操作。实际 Java 资源路由和签名校验另行记录，主机测试不代表 Android 实机效果。

## 维护入口

- `lessons.js`：一句话用途、前后场景、步骤与完成条件、复习题。
- `scenes.js`：12 张可缩放用途图。
- `app-perspective.js`、`app-perspective.css`：目标应用视角的前后变化、重播和减少动画；固定演示数据，不代表设备实测。
- `interactive.js`、`interactive.css`、`index.html`：学习界面和引导层。
- `simulator.js`：纯内存文件与管理接口，按课程 ID 准备初态。
- `prepare-simulator.py`、`build.py`：原样前端复制和资产来源清单。

修改真实 WebUI 后应重新生成资产并核对教程的控件选择器、API 及完成条件。APK 元数据记录源/打包双哈希；除注入的 HTML 外不允许悄悄修改演练控件。
