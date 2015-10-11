# GmSSL

GmSSL(国密SSL)是支持国密算法和标准的OpenSSL分支，增加了对国密SM2/SM3/SM4算法和ECIES、CPK、ZUC算法的支持，实现了这些算法与EVP API和命令行工具的集成。

GmSSL的`libcrypto`密码库增加的密码算法包括：

- SM2是国密椭圆曲线公钥密码标准，其中包含数字签名、公钥加密和密钥交换三个具体方案，以及一个256比特素域上的推荐椭圆曲线参数。GmSSL内置了SM2的推荐曲线参数，实现了SM2的签名算法和公钥加密算法。
- SM3是国密密码杂凑算法标准，输出的杂凑值长度为256比特。
- SM4是国密分组密码标准，又名SMS4，其分组长度和密钥长度均为128比特。GmSSL实现了SMS4密码及SMS4的ECB、CBC、CFB、OFB等工作模式。
- X9.63 KDF是密钥派生函数国际标准之一，ECIES和SM2公钥加密方案依赖该算法，GmSSL实现了X9.63 KDF，并用于支持ECIES和SM2公钥加密。
- ECIES (Elliptic Curve Integrated Encryption Scheme)是椭圆曲线公钥加密的国际标准，可用于加密数据。
- CPK是由南相浩和陈钟设计的基于身份的密码。GmSSL实现了CPK的系统建立和密钥生成算法，生成的密钥可以用于DSA、ECDH、ECDSA、ECIES、SM2等公钥密码算法。
- ZUC(祖冲之算法)是由我国设计的序列密码，以32位字为单位输出密钥流，其密钥长度和IV长度均为128比特。GmSSL的ZUC算法处于开发中。

GmSSL提供命令行工具`gmssl`，可用于生成SM2签名、SM3摘要、HMAC-SM3消息认证码，支持SM4和ZUC数据加解密。

``` bash
$ echo -n abc | gmssl dgst -sm3
66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0
```

显示SM2推荐椭圆曲线域参数

``` bash
$ gmssl ecparam -text -noout -name sm2p256v1 -param_enc explicit
```

在代码目录`./certs/sm2/`目录中给出了SM2证书的例子，可以用`gmssl`工具进行解析
```
$ gmssl x509 -text -noout -in certs/sm2/sm2-x509.pem
$ gmssl pkcs7 -print_certs -in certs/sm2/sm2-pkcs7.pem
```



GmSSL新增的EVP对象包括`EVP_sm3()`、`EVP_sm4_ecb()`、`EVP_sm4_cbc()`、`EVP_sm4_ofb()`、`EVP_sm4_cfb()`和`EVP_zuc()`。









## 安装

``` bash
./Configure darwin64-x86_64-cc --prefix=/usr/local --openssldir=/usr/local/openssl
make
sudo make install
```



## 注意事项

### SM2签名中的摘要生成

SM2数字签名方案中被签名的杂凑值不仅仅是消息的杂凑值，而是签名者身份信息串联上消息的杂凑值，其中签名者身份信息是签名者的可辨别标识字串、椭圆曲线方程系数、生成元和签名者公钥串联后字串的杂凑值。SM2标准中并未说明签名者的可辨别标识字串格式及获得方式，应用可以采用X.509证书中的Subject字段、CN (CommonName)或自行规定。

### SM2参数选择

SM2标准中规定采用256比特的椭圆曲线域参数，并采用256比特的密码杂凑算法，并规定某些步骤中须采用SM3。GmSSL的实现支持灵活的参数设定，并支持内置的所有密码杂凑算法，因此应用可以选择安全程度更高的椭圆曲线域参数和密码杂凑算法，如521比特的域参数和SHA-512算法。

### 国密对SSL/TLS的扩展

国密《中华人民共和国密码行业标准(GM/T 0024-2014) SSL VPN技术规范》在RFC 4346 (TLS 1.1)的握手协议基础上增加了基于ECC和IBC的认证模式和密钥交换模式，增加的相关密码套件包括：

1. ECDHE_SM4_SM3  {0xe0,0x11}
2. ECC_SM4_SM3 {0xe0,0x13}
3. IBSDH_SM4_SM3 {0xe0,0x15}
4. IBC_SM4_SM3 {0xe0,0x17}
5. RSA_SM4_SM3 {0xe0,0x19}
6. RSA_SM4_SHA1 {0xe0,0x1a}

## 开发计划

- 版本号的定义
- 在EVP_PKEY中增加对ECIES和SM2的支持
- 增加对Pairing、IBE和SM9的支持
- 增加对SSL的支持
- 通过ENGINE机制增加对密码硬件设备的支持
