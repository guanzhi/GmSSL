
# SDF

SDF模块用于支持SDF密码卡硬件。目前这部分代码完全是从GmSSL 2.x中移植过来，并移除了对OpenSSL的依赖。

源文件包括：

* `sdf.h`, `sgd.h`，这两个头文件来自于SDF的标准
* `sdf_ext.h`，即原来的`gmsdf.h`，为SDF接口增加了一些辅助功能。实现在`sdf_ext.c`中。
* `sdf_int.h`，`sdf_meth.c`实现了对SDF动态库函数的调用，将SDF动态库转换为一个SDF的对象（包含函数指针）
* `sdf_lib.c`，调用SDF_METHOD，实现了sdf.h的功能
* `sdf_sansec.h/c`，针对三未信安密码卡非标准功能的支持
* `sdfutil.c`，一个访问SDF密码卡的命令行程序

后续工作：

* 在gmssl的API中融入对SDF的支持。以相对ENGINE更轻量级的方式来实现。
