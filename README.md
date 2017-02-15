## 关于GmSSL

GmSSL是一个开源的密码工具箱，支持SM2/SM3/SM4/SM9等国密(国家商用密码)算法、SM2国密数字证书及基于SM2证书的SSL/TLS安全通信协议，支持国密硬件密码设备，提供符合国密规范的编程接口与命令行工具，可以用于构建PKI/CA、安全通信、数据加密等符合国密标准的安全应用。GmSSL项目是[OpenSSL](https://www.openssl.org)项目的分支，并与OpenSSL保持接口兼容。因此GmSSL可以替代应用中的OpenSSL组件，并使应用自动具备基于国密的安全能力。GmSSL项目采用对商业应用友好的类BSD开源许可证，开源且可以用于闭源的商业应用。GmSSL项目由北京大学[关志](http://infosec.pku.edu.cn/~guanzhi/)副研究员的密码学研究组开发维护，项目源码托管于[GitHub](https://github.com/guanzhi/GmSSL)。自2014年发布以来，GmSSL已经在多个项目和产品中获得部署与应用，并获得2015年度“一铭杯”中国Linux软件大赛二等奖(年度最高奖项)与[开源中国](https://www.oschina.net/p/GmSSL)密码类推荐项目。GmSSL项目的核心目标是通过开源的密码技术推动国内网络空间安全建设。

## 最新动态

- 2017年2月12日 支持完整的密码库Java语言封装[GmSSL-Java-Wrapper](http://gmssl.org/docs/java-api.html)
- 2017年1月18日 更新了项目主页
- [更多 ...](http://gmssl.org/docs/changelog.html)

## 国密算法

国密算法是国家商用密码算法的简称。自2012年以来，国家密码管理局以《中华人民共和国密码行业标准》的方式，陆续公布了SM2/SM3/SM4等密码算法标准及其应用规范。其中“SM”代表“商密”，即用于商用的、不涉及国家秘密的密码技术。其中SM2为基于椭圆曲线密码的公钥密码算法标准，包含数字签名、密钥交换和公钥加密，用于替换RSA/Diffie-Hellman/ECDSA/ECDH等国际算法；SM3为密码哈希算法，用于替代MD5/SHA-1/SHA-256等国际算法；SM4为分组密码，用于替代DES/AES等国际算法；SM9为基于身份的密码算法，可以替代基于数字证书的PKI/CA体系。通过部署国密算法，可以降低由弱密码和错误实现带来的安全风险和部署PKI/CA带来的开销。

## 快速上手

快速上手指南介绍GmSSL的编译、安装和`gmssl`命令行工具的基本指令。

1. 下载源代码，解压缩至当前工作目录

   ```sh
   $ tar xzvf gmssl-<version>.tar.gz
   ```

2. 编译与安装

   Linux平台（其他平台的安装过程见[编译与安装](http://gmssl.org)）

   ```sh
   $ ./config
   $ make
   $ sudo make install
   ```

   安装之后可以执行`gmssl`命令行工具检查是否成功

   ```sh
   $ gmssl version
   GmSSL 1.3.0 - OpenSSL 1.0.2d
   ```

3. SM4加密文件

   ```sh
   $ gmssl sms4 -e -in <yourfile> -out <yourfile>.sms4
   enter sms4-cbc encryption password: <your-password>
   Verifying - enter sms4-cbc encryption password: <your-password>
   ```

   解密

   ```sh
   $ gmssl sms4 -d -in <yourfile>.sms4
   enter sms4-cbc decryption password: <your-password>
   ```

4. 生成SM3摘要

   ```
   $ gmssl sm3 <yourfile>
   SM3(yourfile)= 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0
   ```

5. 生成SM2密钥并签名

   ```sh
   $ gmssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:sm2p256v1 \
                   -pkeyopt ec_param_enc:named_curve  -out signkey.pem
   $ gmssl pkeyutl -sign -pkeyopt ec_sign_algor:sm2 -inkey signkey.pem \
                   -in <yourfile> -out <yourfile>.sig
   ```

   可以将公钥从`signkey.pem`中导出并发发布给验证签名的一方

   ```sh
   $ gmssl pkey -in signkey.pem -out vrfykey.pem
   $ gmssl pkeyutl -verify -pkeyopt ec_sign_algor:sm2 -inkey vrfykey.pem \
                   -in <yourfile> -sigfile <yourfile>.sig
   ```


## 项目文档

- 用户手册
   * [编译与安装](http://gmssl.org/docs/install.html)
   * [命令行工具手册](http://gmssl.org/docs/commands.html)
   * [GmSSL EVP API](http://gmssl.org/docs/evp-api.html)
   * [GmSSL Java API](http://gmssl.org/docs/java-api.html)
- 密码算法
   * [SM1分组密码](http://gmssl.org/docs/sm1.html)
   * [SSF33分组密码](http://gmssl.org/docs/ssf33.html)
   * [SM2椭圆曲线公钥密码](http://gmssl.org/docs/sm2.html)
   * [SM3密码杂凑算法](http://gmssl.org/docs/sm3.html)
   * [SM4/SMS4分组密码](http://gmssl.org/docs/sm4.html)
   * [SM9基于身份的密码](http://gmssl.org/docs/sm9.html)
   * [ZUC序列密码](http://gmssl.org/docs/zuc.html)
   * [CPK组合公钥密码](http://gmssl.org/docs/cpk.html)
   * [BF-IBE (Boneh-Franklin Identity-Based Encryption)](http://gmssl.org/docs/bfibe.html)
   * [BB<sub>1</sub>-IBE (Boneh-Boyen Identity-Based Encryption)](http://gmssl.org/docs/bb1ibe.html)
- 密码硬件
   * [密码硬件支持](http://gmssl.org/docs/crypto-devices.html)
   * [国密SKF密码硬件](http://gmssl.org/docs/skf.html)
   * [国密SDF密码硬件](http://gmssl.org/docs/sdf.html)
   * [密钥管理服务](http://gmssl.org/docs/keyservice.html)
- 安全协议
   * [SSL/TLS协议](http://gmssl.org/docs/ssl.html)
   * [国密SSL VPN协议](http://gmssl.org/docs/sslvpn.html)
   * [国密IPSec VPN协议](http://gmssl.org/docs/ipsecvpn.html)
- 开发者
   * [GmSSL编码风格 (Coding Style)](http://gmssl.org/docs/gmssl-coding-style.html)
   * [开发路线 (Road Map)](http://gmssl.org/docs/roadmap.html)
   * [开源许可证 (GmSSL Licenses)](http://gmssl.org/docs/licenses.html)
- 标准与规范
   * [中华人民共和国密码行业标准](http://gmssl.org/docs/standards.html)
   * [国密算法标识OID](http://gmssl.org/docs/oid.html)
