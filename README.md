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

## 功能备注：
APP应用程序拿到ROOT权限的唯一方法就是得到ROOT密匙，此密匙为48位的随机字符串，安全可靠，如若感觉长度不够，可自行修改源码拓展长度。

其中【注入su到指定进程】只支持授权su到64位的APP，老式32位APP不再进行支持，因市面上几乎所有APP都是64位，例如MT文件管理器、Root Explorer文件管理器等等。

## 使用流程：
#### 1.通过拖拽内核文件置find_proc_pid_status可直接得到函数proc_pid_status的入口地址，IDA跳至该地址后按F5，肉眼可得task_struct结构体里cred与seccomp的偏移值。
#### 2.通过拖拽内核文件置find_avc_denied可得相关函数的入口地址，IDA跳至该地址后按F5，肉眼跳转可得avc_denied的入口位置。
#### 3.通过拖拽内核文件置find_do_execve可直接得到函数do_execve的入口位置。
#### 4.通过拖拽内核文件置patch_kernel_root，输入以上得到的信息值，开始补丁内核，同时会自动生成ROOT密匙，直至补丁完成。
#### 5.启动PermissionManager，输入ROOT密匙值，开始享受舒爽的ROOT环境。

想要从没有源码的内核文件中得到这4个值的方法其实有很多，至少有4种以上，其实直接用IDA搜一下就有了~，这里为了大家方便，简易制作了三个“脚本工具”并附其源码。

 
## 效果：
#### 实验数百台机器，全部稳定运行（如红米K20\K30\K40\K50\K60、小米8\9\10\11\12\13、小米平板5、红魔5\6\7、联想、三星、一加、ROG2\3等等）
#### 过市面上所有主流APP的ROOT检测，如农业XX、交X12XX3等...
#### 无需理会谷歌GKI
#### 让所有的ROOT检测手段都回归尘土吧，愿世界迎来一个美好的ROOT时代！

![image](https://github.com/abcz316/linuxKernelRoot/blob/master/ScreenCap/1.png)
![image](https://github.com/abcz316/linuxKernelRoot/blob/master/ScreenCap/2.png)
![image](https://github.com/abcz316/linuxKernelRoot/blob/master/ScreenCap/3.png)
![image](https://github.com/abcz316/linuxKernelRoot/blob/master/ScreenCap/4.png)
