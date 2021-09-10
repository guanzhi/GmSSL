# 命令行工具

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

