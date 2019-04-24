[TOC]
# 前言
&emsp;&emsp;我司做区块链开发，需要用到`国密`。考察了多个国密库，最终选择Gmssl，因为它的性能是最好的。同时，C库作为底层实现，上层可以支持java/golang/c++都没有问题。  

    各个国密库之间是无法兼容的，所以golang/java必须要用相同的国密库，这就只能选择C或者C++了。
&emsp;&emsp;但是，该库是类比Openssl写的，所以，接口都是基于pem（证书）文件格式的。而我们`区块链`一般只需要实际的数据（`二进制数据`或者直接`hex数据`）就够了。  
　　所以，本人及同事合作，对Gmssl进行了封装，就是为了方便golang/java使用。  

# 项目说明
## 一、 目录结构
```
gmssl/blockchain  
  ├── csm2  
  │   ├── sm2.h  
  │   ├── sm2.bin.c  
  │   └── sm2.hex.c  
  │   
  ├── gosm2    
  |   ├── sm2.h      //用到的头文件;
  |   ├── build.go   //c库相关配置;
  |   ├── sm2bin.go
  |   ├── sm2bin.go 
  │   └── sm2_test.go //单位测试、性能测试代码;
  │   
  ├── javasm2   
  │                                    
  └── test    
      ├── c  
      |   ├── mian_win.c  //windows测试代码。
      │   └── main.c      //linux测试代码。
      │   
      ├── java   
```
## 二、 说明
### 1、csm2
&emsp;&emsp;该目录放的是对gmssl封装的接口，方便blockchain开发使用。linux/windows平台经过测试，是没有问题的。  

  由于 gmssl/openssl 本身跨平台的特性，理论上来说，这里的代码也是支持跨平台的。因为我这里用的是标准C，平台无关的。
#### 1.1 、接口类型：
- xxx_bin: 参数、返回值都是以二进制数据传输。具体实现在`sm2.bin.c`。
- xxx_hex: 参数、返回值，都是以二进制数据的hex格式传输`sm2.hex.c`。

  本质上来说，`私钥`就是一个`大整数`，`公钥`就是一个`点`（有两个大整数组成）。`签名`，就是也是`两个大整数`（r/s)。  

  所以，`公钥`、`私钥`、`签名` 本质上来说就是`大整数`组成。大整数，可以直接用`二进制数据`表示。不过，为了可读性，许多时候会把二进制数据转为`hex字符串`。

#### 1.2 、函数说明
- 1、GetPublicKeyByPriv_hex/GetPublicKeyByPriv_bin
  - 私钥生成。如果失败，返回NULL.
- 2、GeneratePrivateKey_hex/GeneratePrivateKey_bin
  - 通过私钥生成公钥。如果失败，返回NULL.
- 3、Sign_hex/Sign_bin
  - 私钥对数据进行签名。如果失败，返回NULL.
- 4、Verify_hex/Verify_bin
  - 公钥对数据+签名进行验签。验签成功返回1，验签失败返回0.
    - 因为c函数没有bool类型，所以只能用0表示false，1表示true（同gmssl）。

#### 1.3 、性能相关
### 1、性能
在4C8G情况下，分别4个函数都跑一遍（生成私钥，签名；私钥生成公钥，验签），平均耗时在500+us（600us以内）。（us表示微妙）
### 2、内存
  通过VC2015，解决了所有的内存泄漏。我跑的C代码的测试用例，内存基本维持在5M以内。
### 3、性能优化
  通过gperftools，发现性能主要消耗在`EC_GROUP_new_by_curve_name`（`EC_KEY_new_by_curve_name`也会调用该函数），达到`20%~30%`。所以，这里优化的一个方向就是：Group（或者说是key）是否可以cache？

### 2、gosm2
#### 2.1 说明
- 接口： 同样的，接口也一样分为xxx_bin/xxx_hex;
- 开发： 
  - 1、就直接将csm2代码拷贝到go文件中;将csm2的h文件内容拷贝过来。
    - 就是说，完全不依赖csm2.
  - 2、build.go用于放置一些编译相关的参数设置，比如lib目录，比如openssl头文件目录。
  - 3、用benchmark测试，发现bin和hex性能相差不大，相对c的测试代码有100us的差距。
  - 4、特别注意： 仅仅linux编译、测试通过；windows未进行测试.
    - 这个是因为我本地go配置有问题，go的编译器用的是gcc的。这个暂时没研究过怎么配置。后续有机会研究.
### java
#### 使用
1. 编译完本项目得到libcrypto-1_1-x64.so 和 gmssljni.so（windows下为.dll文件)
2. 将.so文件拷贝到项目目录
3. 初始化SM2ForBlockChain类时指定SM2ForBlockChain.LoadLibrary($$LIBPATH)
4. 通过API调用SM2ForBlockChain的方法
#### API
```java
    public native String GenPrivateKey();
    public native String GetPublicKeyByPriv(String privKeyHex);
    public native String GetPublicKeyByPriv_bin(byte[] privKeyBytes);
    public native String Sign(String privKeyHex, byte[] src, int srcLen);
    public native int Verify(String pubKeyHex, String signatureHex, byte[] src, int srcLen);
```
```
goos: linux
goarch: amd64
BenchmarkSM2_Hex-4                  2000            672097 ns/op
BenchmarkSM2_Hex-4                  2000            678020 ns/op
BenchmarkSM2_Hex-4                  2000            672652 ns/op
BenchmarkSM2_Hex-4                  2000            662203 ns/op
BenchmarkSM2_Hex-4                  2000            668904 ns/op
BenchmarkSM2_Hex-4                  2000            684090 ns/op
BenchmarkSM2_Hex-4                  2000            676703 ns/op
BenchmarkSM2_Hex-4                  2000            675234 ns/op
BenchmarkSM2_Hex-4                  2000            687949 ns/op
BenchmarkSM2_Hex-4                  2000            675299 ns/op

BenchmarkSM2_Binary-4               2000            655759 ns/op
BenchmarkSM2_Binary-4               2000            640074 ns/op
BenchmarkSM2_Binary-4               2000            638367 ns/op
BenchmarkSM2_Binary-4               2000            651798 ns/op
BenchmarkSM2_Binary-4               2000            645114 ns/op
BenchmarkSM2_Binary-4               2000            638173 ns/op
BenchmarkSM2_Binary-4               2000            665201 ns/op
BenchmarkSM2_Binary-4               2000            647287 ns/op
BenchmarkSM2_Binary-4               2000            649436 ns/op
BenchmarkSM2_Binary-4               2000            634790 ns/op
PASS
ok      _/alidata1/knull/gmssl/test/gosm2       27.838s
```

# 其他
## gmssl编译说明
- linux环境编译没啥好说的。
- windows环境编译，参考[国密官方网站windows编译说明](http://gmssl.org/docs/install.html)
  - windows 64位编译（32位直接照操作编译，是没有问题的）
    - 安装VC/perl/nasm（我这里用的是vc2015）
    - perl Configure VC-WIN64A
    - 在命令行nmake就可以了
    - 注意，要用vc命令行。
      - 到`开始`菜单中找到vc的命令行——`Open Visual C++ 2015 x64 Native Build Tools Command Prompt`；
      - 这个命令行是已经配置好vc环境（include/lib)，而且都是库是找的64位的库。
      - 想直接用没配置好的命令行很麻烦，需要配置头文件、库文件；而且库文件有好几个地方，而且默认是32位的，编译会有问题。
  - 重新编译
    - 有的时候需要重新编译（比如编译debug版本的库），直接`nmake clean`会报错（大约是`文件太多了`）
    - 那么就需要删除obj文件。可以直接 `find ./ -name *.obj |xargs rm `(我用的是git的mingw删除的)

## 开源许可证(Licenses)
&emsp;&emsp;由于本人及同事对第一次对开源库进行pr，可能有许多licenses相关的地方没有考虑到。如果这块有问题，欢迎指出，我们会一一修正。
　　我们这里是直接拷贝了gmssl的licenses。

## 感谢
- 首先，当然感谢`gmssl`，提供这个库给我们用。
- 其次，需要感谢`FISCO-BCOS`。
  - openssl的实现太复杂了，直接上手修改太难，所以这里参考了`FISCO-BCOS`C++实现（没有引用他们的代码，应该没有版权问题）
  - 另外，`FISCO-BCOS`的工作人员很热心，咨询他们国密算法的问题，他们也会答复。