# GmSSL

GmSSL是一个开源的密码工具箱，支持SM2/SM3/SM4/SM9等国密(国家商用密码)算法、SM2国密数字证书及基于SM2证书的SSL/TLS安全通信协议，支持国密硬件密码设备，提供符合国密规范的编程接口与命令行工具，可以用于构建PKI/CA、安全通信、数据加密等符合国密标准的安全应用。GmSSL项目是[OpenSSL](https://www.openssl.org)项目的分支，并与OpenSSL保持接口兼容。因此GmSSL可以替代应用中的OpenSSL组件，并使应用自动具备基于国密的安全能力。GmSSL项目采用对商业应用友好的类BSD开源许可证，开源且可以用于闭源的商业应用。GmSSL项目由北京大学[关志](http://infosec.pku.edu.cn/~guanzhi/)副研究员的密码学研究组开发维护，项目源码托管于[GitHub](https://github.com/guanzhi/GmSSL)。自2014年发布以来，GmSSL已经在多个项目和产品中获得部署与应用，并获得2015年度“一铭杯”中国Linux软件大赛二等奖(年度最高奖项)与[开源中国](https://www.oschina.net/p/GmSSL)密码类推荐项目。GmSSL项目的核心目标是通过开源的密码技术推动国内网络空间安全建设。

## 最新动态

- 2017.01.18 更新了项目主页

## 国密算法

国密算法是国家商用密码算法的简称。自2012年以来，国家密码管理局以《中华人民共和国密码行业标准》的方式，陆续公布了SM2/SM3/SM4等密码算法标准及其应用规范。其中“SM”代表“商密”，即用于商用的、不涉及国家秘密的密码技术。其中SM2为基于椭圆曲线密码的公钥密码算法标准，包含数字签名、密钥交换和公钥加密，用于替换RSA/Diffie-Hellman/ECDSA/ECDH等国际算法；SM3为密码哈希算法，用于替代MD5/SHA-1/SHA-256等国际算法；SM4为分组密码，用于替代DES/AES等国际算法；SM9为基于身份的密码算法，可以替代基于数字证书的PKI/CA体系。通过部署国密算法，可以降低由弱密码和错误实现带来的安全风险和部署PKI/CA带来的开销。

## 快速上手

快速上手指南介绍GmSSL的编译、安装和`gmssl`命令行工具的基本指令。

1. 下载源代码，当前稳定版 `gmssl-1.3.0.tar.gz`

2. 解压缩至当前工作目录

   ```sh
   $ tar xzvf gmssl-1.3.0.tar.gz
   ```

3. 编译与安装

   Linux平台（其他平台的安装过程见[编译与安装](http://gmssl.org)）

   ```sh
   $ ./config
   make
   sudo make install
   ```

   安装之后可以执行`gmssl`命令行工具检查是否成功

   ```sh
   gmssl version -a
   ```

4. SM4加解密文件

   ```sh
   gmssl sms4 -a -in <your-file> -out <your-file>.sms4
   ```

   通过SM3哈希算法生成文件摘要

   ```
   gmssl sm3 -in <your-file> -out <your-file>.sm3
   ```


1. SM2签名

   ```sh
   gmssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:sm2p256v1 -pkeyopt ec_param_enc:named_curve  -out signkey.pem

   gmssl pkeyutl -sign -pkeyopt ec_sign_algor:sm2 -inkey signkey.pem -in <yourfile>.sm3 -out <yourfile>.sig
   gmssl 
   ```

## 项目文档

- [编译与安装](https://github.com/guanzhi/GmSSL/wiki/编译和安装)
- 密码算法：[SM1分组密码](https://github.com/guanzhi/GmSSL/wiki/SM1和SSF33分组密码)；[SSF33分组密码](https://github.com/guanzhi/GmSSL/wiki/SM1和SSF33分组密码)；[SM2椭圆曲线公钥密码](https://github.com/guanzhi/GmSSL/wiki/SM2椭圆曲线公钥密码)；[SM3密码杂凑算法](https://github.com/guanzhi/GmSSL/wiki/SM3密码杂凑算法)；[SM4/SMS4分组密码](https://github.com/guanzhi/GmSSL/wiki/SM4分组密码)；[SM9基于身份的密码](https://github.com/guanzhi/GmSSL/wiki/SM9身份密码)；[ZUC序列密码](https://github.com/guanzhi/GmSSL/blob/develop/doc/gmssl/zuc.md)；[CPK组合公钥密码](https://github.com/guanzhi/GmSSL/wiki/CPK组合公钥)
- 安全协议：国密SSL VPN协议；国密IPSec VPN协议
- [GmSSL命令行工具](https://github.com/guanzhi/GmSSL/blob/develop/doc/gmssl/gmsslcli.md)
- [GmSSL编码风格 (GmSSL Coding Style)](https://github.com/guanzhi/GmSSL/blob/develop/doc/gmssl/codingstyle.md)
- GmSSL编程接口：国密应用编程接口(GmSSL SAF/SDF/SKF/SOF API)；GmSSL EVP API](https://github.com/guanzhi/GmSSL/blob/develop/doc/gmssl/evp.md)；[GmSSL Java API](https://github.com/guanzhi/GmSSL/blob/develop/doc/gmssl/java.md)；[国密算法标识OID](https://github.com/guanzhi/GmSSL/blob/develop/doc/gmssl/oid.md)
- [中华人民共和国密码行业标准(共44项)]()


