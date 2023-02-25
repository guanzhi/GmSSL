### SM3命令

SM3是国密密码杂凑算法标准，由国家密码管理局于2010年12月公布。SM3的输出杂凑值长度为256比特(32字节)，与国际标准SHA-256等长。SM3设计安全性为128比特，安全性与256比特椭圆曲线/SM2、SM4/SMS4、AES-128等同。

#### 计算SM3杂凑值

可以通过`gmssl sm3`命令计算输入消息或者文件的SM3杂凑值，`sm3`命令支持从标准输入(stdin)或者从文件中读取数据，以及支持向标准输出(stdout)或者文件中输出杂凑值。

下面的例子中，在类UNIX操作系统终端环境中，`sm3`命令通过管道从标准输入中读取消息字符串并将杂凑值以十六进制数字的格式打印出来。

```shell
$ echo -n abc | gmssl sm3
66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0
```

由于SM3的杂凑值长度为32字节，因此输出的数字长度为64个字符。SM3的标准中给出了一个基本测试向量，当输入的消息为ASCII字符串`"abc"`，也就是以十六进制表示的字节序列`616263`时，SM3计算得到的杂凑值为`66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0`。因此可以验证，`sm3`命令的计算结果是正确的。

需要注意的是，终端环境通常会自动在字符串后面添加换行符，例如在类UNIX环境中，字符串会被自动添加一个字节`0a`，在Windows环境下，字符串会被自动添加两个字节`0d0a`。在这种情况下，`sm3`命令读取到的字节序列就是`6162620a`或者`6162630d0a`，因此不可能计算出正确的杂凑值。在上面的例子中，必须通过`echo`命令的`-n`参数去掉默认添加的换行符，才能生成正确的SM3杂凑值。

在Windows终端环境中，`echo`命令不支持`-n`选项，可以通过`set`命令来实现相同的效果。

```shell
C:\> echo |set/p="abc" | gmssl sm3
66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0
```

#### 输出二进制杂凑值

默认情况下`sm3`命令会输出杂凑值的十六进制数字串，但是也可以通过在命令行中添加`-bin`选项来强制指定输出二进制数据。在下面的例子中，计算字符串的SM3杂凑值并将二进制数据写入文件中，可以通过`ls`命令验证输出杂凑值的文件大小为32字节。

```shell
$ echo -n abc | gmssl sm3 -bin > abc.sm3

$ ls -al abc.sm3
-rw-r--r--  1 guanzhi  staff  32  2 23 14:59 abc.sm3
       0       2      32 abc.sm3
```

命令`sm3`也支持通过`-hex`选项来显式指定输出十六进制数字串。

#### 文件输入输出

`sm3` 命令支持将文件路径作为参数，选项`-in`和`-out`分别用于指定输入文件路径和输出文件路径。下面的例子中计算一个压缩包文件的SM3杂凑值。

```shell
$ gmssl sm3 -in GmSSL-master.zip -out GmSSL-master.zip.sm3
```

SM3杂凑值可以作为文件的高安全校验值。如果可以通过可靠的方式获得一个文件的SM3杂凑值（比如通过下载文件的HTTPS官网），那么就可以通过这个SM3杂凑值来验证获得文件的完整性。用户下载文件后，可以计算这个文件的SM3杂凑值，和官网上公布的杂凑值进行对比，验证文件是完全正确的。

#### 计算SM2签名杂凑值

在SM2数字签名算法标准中，被签名的SM3杂凑值是通过被签名消息、签名方的SM2公钥、签名方的ID字符串共同生成的。如果第三方的SM2签名系统（如硬件的SM2签名机）只支持对SM3杂凑值的签名，不支持对SM2签名算法中的SM3杂凑值生成功能，那么可以用`sm3`命令的`-pubkey`和`-id`选项来生成符合SM2签名要求的杂凑值。其中`-pubkey`选项指定签名方的公钥PEM文件，`-id`选项指定签名方的ID字符串。下面的例子给出了一个完整的SM2密钥生成和杂凑值计算过程。

```shell
$ gmssl sm2keygen -out sm2key.pem -pubout sm2pubkey.pem -pass P@ssw0rd
$ cat sm2pubkey.pem 
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEcG1XVf03Fx1N11K0U8e5ICACpv0X
xBXZm34MjTfdLz1zUHowuC023Pl/8Eq3ZWdgYQdlgdtAe0UM2Sps6K1X5A==
-----END PUBLIC KEY-----

$ echo -n "abc" | gmssl sm3 -pubkey sm2pubkey.pem -id Alice 
e5978b292934966db0f9604d63a3e020a5acb1194df67f2285f42203b5af9efd
```

在第一个命令中，我们用`sm2keygen`生成了一对新的SM2私钥和公钥，其中公钥文件为`sm2pubkey.pem`。这是一个文本类型的文件，因此通过`cat`可以看到这个文件的内容。在最后的`sm3`命令中，增加了`-pubkey`和`-id`参数，可以看到输出的杂凑值不同于`"abc"`的杂凑值。

注意，如果应用没有显示指定如何分配、获得签名方的ID，那么SM2标准指定使用默认的ID字符串`"1234567812345678"`，也就是字节序列`31323334353637383132333435363738`。在指定`-pubkey`选项但是没有指定`-id`选项时，`sm3`命令会使用这个默认的ID字符串。

```
$ echo -n "abc" | gmssl sm3 -pubkey sm2pubkey.pem
9192b2f04f4b14b6e71e68f59ed0936500999231305c651763422a12f8a3b689
$ echo -n "abc" | gmssl sm3 -pubkey sm2pubkey.pem -id 1234567812345678
9192b2f04f4b14b6e71e68f59ed0936500999231305c651763422a12f8a3b689
```

注意，在SM2中使用长度为0的ID字符串是合法的，但是`sm3`命令不支持长度为0的字符串作为输入。可以通过C函数接口来处理长度为0的ID字符串。