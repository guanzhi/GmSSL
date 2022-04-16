# 命令行工具

注意：

* 命令行工具接口在v3版本正式发布前还会有较大调整
* SM2, SM3, SM4等算法的命令相对比较底层，是对C语言接口的简单封装，命令行的应用开发者需要组合使用这些指令

命令行工具：

* `sm3` 计算SM3杂凑值，支持带公钥和ID的Z值计算
* `sm3hmac` 计算SM3-HMAC值
* `sm2keygen` 生成SM2密钥对，以PKCS #8口令加密的PEM格式存储
* `sm2sign`,`sm2verify` SM2签名和验证，生成DER二进制编码的SM2签名值
* `sm2encrypt`,`sm2decrypt` SM2加解密，注意只支持较短的消息加密
* `reqgen` 生成PKCS #10证书签名请求PEM文件
* `reqparse` 解析打印REQ文件
* `reqsign` CA用私钥对REQ文件签名，生成证书
* `certgen`生成自签名证书
* `certparse` 解析打印证书
* `certverify` 验证证书链

TLS功能

* `tlcp_client`
* `tlcp_server`
* `tls12_client`
* `tls12_server`
* `tls13_client`
* `tls13_server`

私钥总是默认以口令加密的方式存储
SM3/HMAC-SM3 以二进制的格式输出
签名和SM2Ciphertext以DER编码输出


应该提供一个口令导出密钥的算法，由口令导出密钥

SM4加密需要外部提供key, iv
HMAC-SM3可以用命令行的方式拼合
因此没必要提供一个单独的SM4-CBC-HMAC-SM3

