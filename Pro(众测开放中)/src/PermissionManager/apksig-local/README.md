# apksig-local（完整本地源码模块）

本目录已内置用户提供的 `apksig-android-master.zip` 的 `src/main/java` **全部 123 个 Java 源文件**。项目仅通过 `implementation project(':apksig-local')` 依赖本模块。

- 上游项目：<https://github.com/MuntashirAkon/apksig-android>
- 固定上游提交：`c120428b7b07f2a2b638c7519c2d60680d6398ce`
- 许可证：Apache License 2.0，详见 `LICENSE`，保留所有源文件版权头。
- 已经不需要任何额外的 `vendor_apksig.py`、PowerShell 下载脚本或者 JitPack。
- 此模块不依赖 `sun-security-android`；现有密钥由 App 使用平台自带 `KeyStore("PKCS12")` 打开。
- Android Studio / Gradle 的 SDK、AGP、AndroidX 等是主工程既有依赖，并不是此签名库的 Maven 依赖。

本次在独立 JDK 测试环境中对全部 123 个签名库 Java 源文件进行 Java 8 编译验证，并使用临时测试证书演示 v2/v3 签名和 apksig 验证。最终仍建议在目标 Android 设备上进行一次真实 B APK 签名与安装测试。
