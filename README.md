# GmSSL

[![CMake](https://github.com/guanzhi/GmSSL/workflows/CMake/badge.svg)](https://github.com/guanzhi/GmSSL/actions/workflows/cmake.yml)

GmSSL是由由北京大学自主开发的国产商用密码开源库，实现了对国密算法、标准和安全通信协议的全面功能覆盖，支持包括移动端在内的主流操作系统和处理器，支持密码钥匙、密码卡等典型国产密码硬件，提供功能丰富的命令行工具及多种编译语言编程接口。


## 主要特性

* 超轻量：GmSSL 3.0大幅度降低了内存需求和二进制代码体积，不依赖动态内存，可以用于无操作系统的低功耗嵌入式环境(MCU、SOC等)，开发者也可以更容易地将国密算法和SSL协议嵌入到现有的项目中。
* 更合规：GmSSL 3.0 可以配置为仅包含国密算法和国密协议(TLCP协议)，依赖GmSSL 的密码应用更容易满足密码产品型号检测的要求，避免由于混杂非国密算法、不安全算法等导致的安全问题和合规问题。
* 更安全：TLS 1.3在安全性和通信延迟上相对之前的TLS协议有巨大的提升，GmSSL 3.0支持TLS 1.3协议和RFC 8998的国密套件。GmSSL 3.0默认支持密钥的加密保护，提升了密码算法的抗侧信道攻击能力。
* 跨平台：GmSSL 3.0更容易跨平台，构建系统不再依赖Perl，默认的CMake构建系统可以容易地和Visual Studio、Android NDK等默认编译工具配合使用，开发者也可以手工编写Makefile在特殊环境中编译、剪裁。

## 下载

* GmSSL的主分支开发中版本为 [GmSSL-3.1.0-dev](https://github.com/guanzhi/GmSSL/archive/refs/heads/master.zip)，主要增加跨平台特性，特别是对Windows/Visual Studio的支持，Windows、Android、iOS平台的开发者需要使用该版本。
* GmSSL当前稳定版本为 [GmSSL-3.0.0](https://github.com/guanzhi/GmSSL/releases/tag/v3.0.0)。

## 编译与安装

GmSSL 3.0 采用了cmake构建系统。下载源代码后将其解压缩，进入源码目录，执行：

```bash
mkdir build
cd build
cmake ..
make
make test
sudo make install
```

### Visual Studio环境编译

在Visual Studio命令提示符下执行：

```bash
mkdir build
cd build
cmake .. -G "NMake Makefiles"
nmake
```

### iOS编译

下载 https://github.com/leetal/ios-cmake ，将`ios.toolchain.cmake`文件复制到`build`目录。

```bash
mkdir build; cd build
cmake .. -G Xcode -DCMAKE_TOOLCHAIN_FILE=../ios.toolchain.cmake -DPLATFORM=OS64
cmake --build . --config Release
```

如果出现“error: Signing for "gmssl" requires a development team.”错误，可以用Xcode打开工程文件，在Signing配置中设置Development Team。

### Android编译

下载Android NDK，执行

```bash
mkdir build; cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=$NDK/build/cmake/android.toolchain.cmake  -DANDROID_ABI=arm64-v8a  -DANDROID_PLATFORM=android-23
make
```

## 主要功能

### 密码算法

* 分组密码：SM4 (CBC/CTR/GCM), AES (CBC/CTR/GCM)
* 序列密码：ZUC/ZUC-256, ChaCha20, RC4
* 哈希函数: SM3, SHA-224/256/384/512, SHA-1, MD5
* 公钥密码：SM2加密/签名, SM9加密/签名
* MAC算法：HMAC, GHASH
* 密钥导出函数：PBKDF2、HKDF
* 随机数生成器：Intel RDRAND, HASH_DRBG (NIST.SP.800-90A)

### 证书和数字信封

* 数字证书：X.509证书, CRL证书注销列表, CSR (PKCS #10) 证书签名请求
* 私钥加密：基于SM4/SM3口令加密的PEM格式私钥 (PKCS #8)
* 数字信封：SM2密码消息 (GM/T 0010-2012)

### SSL协议

* TLCP 1.1，支持密码套`TLS_ECC_SM4_CBC_SM3 {0xE0,0x13}` (GB/T 38636-2020、GM/T 0024-2014)
* TLS 1.2，支持密码套件`TLS_ECDHE_SM4_CBC_SM3 {0xE0,0x11}` (GB/T 38636-2020、GM/T 0024-2014)
* TLS 1.3，支持密码套件`TLS_SM4_GCM_SM3 {0x00,0xC6}`  (RFC 8998)

## 典型应用

#### Nginx-with-GmSSL3.0

GmSSL支持Nginx的适配，并提供了Docker实现，具体参见[Nginx-with-GmSSL3.0](https://github.com/zhaoxiaomeng/Nginx-with-GmSSLv3) 项目。

## Roadmap

- [ ] Add Windows Visual Studio support
- [ ] Add Windows MinGW support
- [ ] Add iOS support and iOS demo App
- [ ] Add Android support
- [ ] **Version 3.1.0 release**
- [ ] Add GCC specific optimization
- [ ] Add X86_64 assembly implementation
- [ ] Add GPU implementation
- [ ] Add performance benchmark tool
- [ ] Add GCM cipher suites
- [ ] Release official open interfaces
- [ ] **Version 3.2.0 release**

