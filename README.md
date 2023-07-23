# SKRoot - SuperKernelRoot - Linux内核级完美隐藏ROOT演示
新一代SKRoot，挑战全网root检测手段，跟面具完全不同思路，摆脱面具被检测的弱点，完美隐藏root功能，全程不需要暂停SELinux，实现真正的SELinux  0%触碰，通用性强，通杀所有内核，不需要内核源码，直接patch内核，兼容安卓APP直接JNI调用，稳定、流畅、不闪退。
## 功能列表：
#### 1.显示自身权限信息
#### 2.获取ROOT权限
#### 3.执行ROOT命令
#### 4.执行原生内核命令
#### 5.安装部署su
#### 6.注入su到指定进程
#### 7.完全卸载清理su

## 效果：
* **实验设备包括：红米K20\K30\K40\K50\K60、小米8\9\10\11\12\13、小米平板5\6、红魔5\6\7、联想、三星、一加、ROG2\3等，支持型号非常多。测试结果显示，SKRoot能够在所支持设备上非常稳定的运行。**
* **过市面上所有主流APP的ROOT检测，如农业XX、交X12XX3等...**
* **无需理会谷歌GKI**
* **让所有的ROOT检测手段都回归尘土吧，愿世界迎来一个美好的ROOT时代！**

![image](https://github.com/abcz316/linuxKernelRoot/blob/master/ScreenCap/1.png)
![image](https://github.com/abcz316/linuxKernelRoot/blob/master/ScreenCap/2.png)
![image](https://github.com/abcz316/linuxKernelRoot/blob/master/ScreenCap/3.png)
![image](https://github.com/abcz316/linuxKernelRoot/blob/master/ScreenCap/4.png)

## 功能备注：
APP应用程序拿到ROOT权限的唯一方法就是得到ROOT密匙，此密匙为48位的随机字符串，安全可靠，如若感觉长度不够，可自行修改源码拓展长度。

其中【**注入su到指定进程**】**只支持授权su到64位的APP**，老式32位APP不再进行支持，因市面上几乎所有APP都是64位，例如MT文件管理器、Root Explorer文件管理器等等。

## 使用流程：
#### 1.通过拖拽内核文件置`find_proc_pid_status`可直接得到函数`proc_pid_status`的入口地址，IDA跳至该地址后按F5，肉眼可得`task_struct`结构体里`cred`或`seccomp`的偏移值（`seccomp`为非必需项）。
#### 2.通过拖拽内核文件置`find_avc_denied`可得相关函数的入口地址，IDA跳至该地址后按F5，肉眼跳转可得`avc_denied`的入口位置。
#### 3.通过拖拽内核文件置`find_do_execve`可直接得到函数`do_execve`的入口位置。
#### 4.通过拖拽内核文件置`patch_kernel_root`，输入以上得到的信息值，开始补丁内核，同时会自动生成ROOT密匙，直至补丁完成。
#### 5.启动`PermissionManager`，输入ROOT密匙值，开始享受舒爽的ROOT环境。
【**避免IDA的BUG**】：请注意，在寻找**seccomp**偏移时，请跳到汇编指令界面**检查汇编指令MOV的实际值**，因为IDA伪代码显示的数值有可能是错误的。

想要从没有源码的内核文件中得到这4个值的方法其实有很多，至少有4种以上，其实直接用IDA搜一下就有了~，这里为了大家方便，简易制作了三个“脚本工具”并附其源码。

## 问题排查：
如发现第三方应用程序依然有侦测行为，请按照以下步骤进行排查：
* **内核必须保证是基于官方原版进行修改，而非自行编译或使用第三方源码编译。**
* **如果你曾经使用过Magisk，你应该先将手机完全刷机，因为Magisk可能会残留日志文件等信息。**
* **不要安装需要ROOT权限的工具，或涉及系统环境检测的应用，如冰箱、黑洞、momo和密匙认证等。这些应用的存在可能会被用作证据，推断你的设备已获取ROOT权限。以冰箱为例，这款应用需要ROOT权限才能运行，如果你的设备上安装了冰箱，那就可能被用来佐证你的设备处于ROOT环境。实际测试中我们发现，"X租号"APP就会进行此类环境检测。因此，我们强烈建议不安装这些工具。若确需使用，请在使用结束后立即卸载，以降低异常环境判断风险。**
* **Android APP应用可能会被检测其特征。这里我们仅提供APP调用的教学，在实际使用中，请尽量隐藏应用，或者考虑卸载应用，改用纯命令行方式调用的testRoot.cpp。**
* **在老旧版本的Android系统中，应用程序无需任何权限即可访问/data/local/tmp目录。在这种情况下，你应该升级Android系统版本，或者卸载SU。**
* **如果你的手机在解锁后会发出警报，你需要自行解决这个问题，因为它与SKRoot无关。**
* **检查应用程序是否在检测Bootloader锁，而不是ROOT权限。如果是这样，你应该安装SKRoot的隐藏Bootloader锁模块。**
* **请检查SELinux状态是否被恶意软件禁用。**
