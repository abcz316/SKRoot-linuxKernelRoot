# SkRoot - LinuxKernelRoot - Linux内核级完美隐藏Root演示
新一代SkRoot，完美隐藏Root功能，挑战全网Root检测手段，实现真正的SELinux 0%触碰、无挂载，通用性强，通杀所有内核，不需要内核源码，直接patch内核，兼容安卓APP直接JNI调用，稳定不闪退。

## SkRoot(Lite)：
完美隐藏Root功能，实现SELinux 0%触碰、无挂载，通杀所有内核，仅提供Root基础功能。
 
## SkRoot(Pro)：
同享完美隐藏Root特性，SELinux零触碰、无挂载，支持授权管理+内核模块（隐藏目录、隐蔽执行sh、解除温控、系统文件无痕伪造等）。

### 模块特性：
支持内核热Hook修改，最高10万Hook点位、0性能损耗，单模块跨全内核通用运行。

## 功能列表：
1.测试ROOT权限

2.执行ROOT命令

3.以ROOT执行程序

4.安装部署su

5.注入su到指定进程

6.完全卸载清理su

7.寄生目标APP
## 效果：
* 实验设备包括：红米K20\K30\K40\K50\K60、小米8\9\10\11\12\13、小米平板5\6、红魔5\6\7、联想、三星、一加、ROG2\3等，支持型号非常多。测试结果显示，SkRoot能够在设备上**非常稳定**的运行。
* **过市面上所有主流App的Root检测，如农业XX、交X12123等...**
* **不需要Linux内核源码、不编译内核，直接修补内核，保留原厂内核优化**
* **支持Linux内核版本：3.10~6.12**

![image](https://github.com/abcz316/SKRoot-linuxKernelRoot/blob/master/Lite_version/%E5%8A%9F%E8%83%BD%E6%88%AA%E5%9B%BE/1.png)
![image](https://github.com/abcz316/SKRoot-linuxKernelRoot/blob/master/Lite_version/%E5%8A%9F%E8%83%BD%E6%88%AA%E5%9B%BE/2.png)
![image](https://github.com/abcz316/SKRoot-linuxKernelRoot/blob/master/Lite_version/%E5%8A%9F%E8%83%BD%E6%88%AA%E5%9B%BE/3.png)

## 功能备注：
1. APP应用程序得到Root权限的唯一方法就是得到Root密匙，此密匙为48位的随机字符串，安全可靠。

2. 其中【**注入su到指定进程**】**只支持授权su到64位的APP**，老式32位App不再进行支持。

## SkRoot(Lite) 使用流程：
1.下载源码编译或**下载编译产物**： [patch_kernel_root.exe](https://github.com/abcz316/SKRoot-linuxKernelRoot/blob/master/Lite_version/build/patch_kernel_root(2026-2-25).exe)、 [PermissionManager.apk](https://github.com/abcz316/SKRoot-linuxKernelRoot/blob/master/Lite_version/build/PermissionManager(2026-2-25).apk)

2.将内核kernel文件拖拽置`patch_kernel_root.exe`即可一键自动化流程补丁内核，同时会自动生成Root密匙。

3.安装并启动`PermissionManager.apk`或者`testRoot`，输入Root密匙值，即可正常使用SkRoot。

## SkRoot(Pro) 使用流程：
***已开发完成，目前正在众测中，稳定后会全部公开。如想加入测试组织，请关注TG频道。https://t.me/skrootabc***

## 更新日志：
2026-2：
  * **1.修复su无法独立后台运行的问题**
  * **2.修复Linux 4.4无法解析的问题。**

2026-1：
  * **1.修复审计日志残留痕迹**

2025：
  * **1.适配Linux6.12**
  * **2.修复su部分命令无法执行的问题。**
  * **3.修复su进程切后台会被系统冻结的BUG**
  * **4.修复su进程不能退出有残留的问题**
  * **5.修复部分Linux 4.x会死机、无法解析的问题**
  * **6.修复Linux 6.1、6.6及以上无法解析问题**
  * **7.新增内核隐藏su路径（抵御安卓漏洞）**
  * **8.新增以Root身份直接执行程序功能**
  * 
2024：
  * **1.新增永久授权su功能**

2023：
  * **1.新增seccomp补丁代码**
  * **2.新增寄生目标功能**
  * **3.新增一键自动化流程补丁内核功能**
  * **4.修复Linux 3.X老内核兼容问题**
  * **5.修复Linux 5.10、5.15无法开机问题**

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
* **如果在解锁BL后手机会发出警报，你需要自行解决这个问题，因为它与SkRoot无关。**
* **如果对方是检测BL锁，而不是Root权限。你应该安装SkRoot的隐藏BL锁模块。**
* **请检查SELinux状态是否被恶意软件禁用。**

3、耗电风险须知：
* **我们不提倡任何自行编译内核的行为，可能会造成续航缩短、发烫等问题，因其丢失了原厂的功耗管理策略。SkRoot则是在原厂内核上进行修补，保留原厂调教，无任何耗电问题。**
