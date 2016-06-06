# GmSSL

GmSSL [(http://gmssl.org)](http://gmssl.org) 是支持国密算法和标准的OpenSSL分支，是一个提供了丰富密码学功能和安全功能的开源软件包。在保持OpenSSL原有功能并实现和OpenSSL API兼容的基础上，GmSSL新增多种密码算法、标准和协议，其中包括：

* 椭圆曲线公钥加密国际标准ECIES
* 国密SM2椭圆曲线公钥密码标准，包含数字签名算法、公钥加密算法、密钥交换协议及推荐椭圆曲线参数
* 国密SM3密码杂凑算法、HMAC-SM3消息认证码算法、PBKDF2口令加密算法
* 国密SM4/SMS4分组密码、ECB/CBC/CFB/OFB/CTR/GCM/FFX加密模式和CBC-MAC/CMAC消息认证码算法
* 组合公钥(CPK)身份密码，可同时支持椭圆曲线国际标准算法和国密标准算法
* 国密动态口令密码规范
* 祖冲之(ZUC)序列密码

GmSSL还可以以安全中间件的方式访问PCI-E密码加速卡、USB Key等硬件密码设备，为上层应用提供密钥安全存储、密码计算硬件加速以及国密SM1分组密码、国密SSF33分组密码等硬件实现的保密算法。GmSSL通过ENGINE机制支持符合不同接口规范的密码设备：

* 提供国密算法和国密SKF接口规范实现的硬件密码设备
* 提供Windows Crypto API Provider的密码硬件设备
* 提供PKCS #11 (Cryptoki)接口实现的密码硬件设备

GmSSL主要包含通用密码库`libcrypto`、SSL/TLS协议库`libssl`和命令行工具`gmssl`。除`gmssl`的命令行接口之外，GmSSL还通过`libcrypto`密码库提供原生的EVP API抽象密码接口以及国密智能IC卡及智能密码钥匙密码应用接口SKF API，以及通过JNI (Java Native Interface)本地接口实现的Java语言绑定。

为了便于商业软件安全地采用GmSSL，GmSSL保持了和OpenSSL相似的BSD/Apache风格的许可证，因此闭源软件或者商业软件可以安全地在产品中采用GmSSL的代码。自发布以来GmSSL荣获开源中国[(http://oschina.net)](http://oschina.net)密码类推荐开源项目、2015年度“一铭杯”中国Linux软件大赛二等奖(该年度最高奖项)等奖励和荣誉。

GmSSL项目目前由北京大学信息安全实验室开发和维护，项目的长期目标是推动国产密码算法在国内互联网和开源领域的广泛应用，提高国内商用非涉密领域的自主密码应用水平。

## 编译和安装

OpenSSL通过其独有的编译脚本支持非常广泛的硬件和操作系统，GmSSL项目力求保持其跨平台特性。目前GmSSL可以在Linux平台和苹果OS X平台顺利编译安装，在Windows上暂时无法编译通过。我们预计可以在下一个版本发布时修正Windows平台的编译问题。

在Linux平台上通过如下指令实现编译和安装：

```
./config
make
make install
```

在苹果OS X操作系统上通过如下指令实现编译和安装：
```
./Configure darwin64-x86_64-cc --prefix=/usr/local --openssldir=/usr/local/openssl
make
sudo make install
```

