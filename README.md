# SKRoot - Linux 内核级完美隐藏 Root 方案

新一代 SKRoot，完美隐藏Root功能，无视全网检测手段，**实现SELinux零触碰、无挂载！** 通杀所有内核，**免源码直接 Patch 原厂内核，完美保留官方内核所有特性**。✅

## 版本对比

| 对比项 | 🟢 SKRoot (Lite) | 🚀 SKRoot (Pro) |
| :--- | :--- | :--- |
| **隐蔽性** | **完美隐藏** Root、SELinux 零触碰、无挂载。 | **完美隐藏** Root、SELinux 零触碰、无挂载。 |
| **形态** | **寄生**于其他 APP 内，**无外显实体**。 | **寄生**于其他 APP内，**无外显实体**。  |
| **用途** | **稳定和兼容性**优先。 | **更深度的功能扩展**。 |
| **功能** | **核心 Root 环境**。 | **授权管理 + 内核模块 + 免解/越狱/漏洞利用**。 |
| **漏洞利用** | - | CVE-2026-43499：**漏洞利用后环境修复** |
| **进阶** | - | 隐藏目录、隐蔽执行sh、解除温控、系统文件无痕伪造等。 |
| **模块能力** | - | 支持**用户态、内核态自由切换执行**。<br>**自研内核Hook框架：0性能损耗、无侧信道痕迹**。<br>内核偏移**动态寻找**：真正**跨内核运行** 。 |


***SKRoot模块介绍**：支持在用户态与内核态之间灵活切换，非常强大；内核偏移由开发 SDK 接口统一提供，一次编译即可跨所有内核通用（3.10~6.12）；同时自带 Hook 框架，0 性能损耗，无视侧信道检测。*

## 功能列表：
1.测试ROOT权限

2.执行ROOT命令

3.以ROOT执行程序

4.安装部署su

5.注入su到指定进程

6.完全卸载清理su

7.寄生目标APP
## 效果：
* 实验设备包括：红米K20\K30\K40\K50\K60、小米8\9\10\11\12\13、小米平板5\6、红魔5\6\7、联想、三星、一加、ROG2\3等，支持型号非常多。测试结果显示，SKRoot能够在设备上**非常稳定**的运行。
* **过市面上所有主流App的Root检测，如农业XX、交X12123等...**
* **不需要Linux内核源码、不编译内核，直接修补内核，保留原厂内核优化**
* **支持Linux内核版本：3.10~6.12**

![image](https://github.com/abcz316/SKRoot-linuxKernelRoot/blob/master/Lite_version/%E5%8A%9F%E8%83%BD%E6%88%AA%E5%9B%BE/1.png)
![image](https://github.com/abcz316/SKRoot-linuxKernelRoot/blob/master/Lite_version/%E5%8A%9F%E8%83%BD%E6%88%AA%E5%9B%BE/2.png)
![image](https://github.com/abcz316/SKRoot-linuxKernelRoot/blob/master/Lite_version/%E5%8A%9F%E8%83%BD%E6%88%AA%E5%9B%BE/3.png)

## 功能备注：
1. APP应用程序得到Root权限的唯一方法就是得到Root密匙，此密匙为48位的随机字符串，安全可靠。

2. 其中【**注入su到指定进程**】**只支持授权su到64位的APP**，老式32位App不再进行支持。

## SKRoot(Lite) 使用流程：
1.下载源码编译或**下载编译产物**： [patch_kernel_root.exe](https://github.com/abcz316/SKRoot-linuxKernelRoot/releases/download/Lite_v2026.6.1/patch_kernel_root.2026-6-1.exe)、 [skroot_lite.apk](https://github.com/abcz316/SKRoot-linuxKernelRoot/releases/download/Lite_v2026.6.1/SKRoot_Lite.2026-6-1.apk)

2.将内核kernel文件拖拽置`patch_kernel_root.exe`即可一键自动化流程补丁内核，同时会自动生成Root密匙。

3.安装并启动`skroot_lite.apk`或者`testRoot`，输入Root密匙值，即可正常使用SKRoot。

## SKRoot(Pro) 使用流程：
*已全部开发完成，其中 “[SKRootPro 模块开发 SDK](https://github.com/abcz316/SKRoot-linuxKernelRoot/tree/master/Pro(%E4%BC%97%E6%B5%8B%E5%BC%80%E6%94%BE%E4%B8%AD)/src/testModule)”、“[SKRoot 模块开发指南.pdf](https://github.com/abcz316/SKRoot-linuxKernelRoot/blob/master/Pro(%E4%BC%97%E6%B5%8B%E5%BC%80%E6%94%BE%E4%B8%AD)/src/testModule/SKRoot%E6%A8%A1%E5%BC%80%E5%8F%91%E6%8C%87%E5%8D%97.pdf)” 已公开，其余组件将在稳定后逐步公开。*

*目前正在众测中。如想加入测试组织，请关注TG频道：[t.me/skrootabc](https://t.me/skrootabc)*

## 更新日志：
2026-6：
  * 1.修复 Linux 内核有金丝雀的兼容性问题。
  
2026：
  * 1.修复审计日志残留痕迹问题。
  * 2.修复 su 后台运行、/data/data 访问以及命令根目录异常等兼容问题。
  * 3.增强内核修补兼容性，修复 Linux 4.4、4.x、5.15、6.12 等部分内核版本的适配问题。
  * 4.修复 CONFIG_THREAD_INFO_IN_TASK 判断错误导致的内核识别异常。
  * 5.修复部分华为/荣耀、华为 nova 2s、红米 K20 等设备无法修补或无法正常开机的问题。
  * 6.增强寄生 App 功能稳定性。
  
2025：
  * 1.适配Linux6.12。
  * 2.修复su部分命令无法执行的问题。
  * 3.修复su进程切后台会被系统冻结的BUG。
  * 4.修复su进程不能退出有残留的问题。
  * 5.修复部分Linux 4.x会死机、无法解析的问题。
  * 6.修复Linux 6.1、6.6及以上无法解析问题。
  * 7.新增内核隐藏su路径（抵御安卓漏洞）。
  * 8.新增以Root身份直接执行程序功能。

2024：
  * 1.新增永久授权su功能。

2023：
  * 1.新增seccomp补丁代码。
  * 2.新增寄生目标功能。
  * 3.新增一键自动化流程补丁内核功能。
  * 4.修复Linux 3.X老内核兼容问题。
  * 5.修复Linux 5.10、5.15无法开机问题。

## 问题排查：
1、如遇到Linux 6.0以上内核无法开机，请阅读：
* **请不要使用Android.Image.Kitchen进行打包，该工具不支持Linux 6.0以上内核！**
* **可使用magiskboot进行打包。**
* **magiskboot的快速获取方式：使用7z解压[Magisk.apk](https://github.com/topjohnwu/Magisk/releases)，把lib/x86_64文件夹里的libmagiskboot.so直接改名magiskboot即可使用。因为这是个Linux可执行文件，并不是动态库，不要被名字带so字样所迷惑。**
* **magiskboot官方没有提供Windows版本，请安装Linux系统使用它。不建议使用非官方的Windows版本，因为代码版本可能太旧。**
* **解包命令：./magiskboot unpack boot.img**
* **打包命令：./magiskboot repack boot.img**

2、如发现第三方应用程序依然有侦测行为，请按照以下步骤进行排查：
* **内核必须保证是基于官方原版进行修改，而非自行编译或使用第三方源码编译。**
* **如果你曾经使用过Magisk，你应该先将手机完全刷机，因为Magisk可能会残留日志文件等信息。**
* **不要安装需要Root权限的工具，或涉及系统环境检测的应用，如冰箱、黑洞、momo和密匙认证等。这些应用的存在可能会被用作证据，推断你的设备已获取Root权限。若需使用，请在使用后立即卸载。**
* **App可能会被特征检测。这里的App只是演示功能写法。在实际使用中，请尽量隐藏App。例如使用寄生功能，寄生到其他无害的App内，以免被侦测。**
* **如果在解锁BL后手机会发出警报，你需要自行解决这个问题，因为它与SKRoot无关。**
* **如果对方是检测BL锁，而不是Root权限。你应该安装SKRoot的隐藏BL锁模块、或开启“免解越狱”模式。**
* **请检查SELinux状态是否被恶意软件禁用。**

3、耗电风险须知：
* **我们不提倡任何自行编译内核的行为，可能会造成续航缩短、发烫等问题，因其丢失了原厂的功耗管理策略。SKRoot是在原厂内核上进行修补，完美保留原厂调教，无任何耗电问题。**
