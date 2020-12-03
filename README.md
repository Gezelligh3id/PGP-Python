## 使用Python实现PGP算法

环境：

+ Pycharm 2020.3
+ Python 3.8 + zlib + base64 + codecs
+ 实现基于武汉大学出版社《应用密码学》

### 一、PGP简介

PGP是于1990年左右由Philip Zimmermann编写的密码软件。 PGP支持多个平台，版本包括商用版和免费版，此外还有一个GNU遵照OpenGPG（RFC4880）规范编写的叫做GnuPG（GNU Privacy Guard）的免费软件。

### 二、PGP加密过程

![image-20201129182432696](C:\Users\think\AppData\Roaming\Typora\typora-user-images\image-20201129182432696.png)

2.1 邮件数据M经MD5进行压缩处理，形成数据的摘要。

2.2 用发送者的RSA私钥Kd对摘要进行数字签名，以确保真实性。

2.3 将邮件数据与数字签名拼接：数据在前，签名在后。

2.4 用ZIP对拼接后的数据进行压缩，以便于存储和传输。

2.5 用IDEA对压缩后的数据进行加密，加密钥为K，以确保秘密性。

2.6 用接受者的RSA公钥Ke加密IDEA的密钥K。

2.7 将经RSA加密的IDEA密钥与经IDEA加密的数据拼接:数据在前，密钥在后。

2.8 将加密数据进行BASE 64变化，变化成ASCII码。因为许多E-mail系统只支持ASCII码数据。

### 三、PGP解密过程

![image-20201129184739590](C:\Users\think\AppData\Roaming\Typora\typora-user-images\image-20201129184739590.png)

3.1 将加密后的ASCII码进行BASE64解码，变成加密数据。

3.2 将加密数据中的经RSA加密的IDEA密钥与经IDEA加密的数据分开。

3.3 使用接受者的RSA私钥Kd解密IDEA的密钥K。

3.4 使用IDEA密钥K解密经IDEA加密的数据。

3.5 将解密后的数据进行解压缩，以便于阅读。

3.6 将邮件数据与数字签名分开，数据在前，签名在后。

3.7 用发送者的RSA公钥Ke对签名解密。

3.8 对解密后的邮件数据进行MD5压缩，验证生成的数字签名与3.7中解密的签名是否相同。

### 四、用到的加密算法

#### 4.1 **单向散列函数**-MD5算法

+ **单向散列函数：** 

  PGP可以使用单向散列函数计算和显示消息的散列值。可以使用的单向散列函数算法包括MD5、SHA-1等。

+ **MD5算法过程：**

  MD5算法的功能为输入任意长度的信息，经过处理，输出为128位的信息。对MD5算法简要的叙述可以为：MD5以512位分组来处理输入的信息，且每一分组又被划分为16个32位子分组，经过了一系列的处理后，算法的输出由四个32位分组组成，将这四个32位分组级联后将生成一个128位散列值。

  (1) 填充：如果输入信息的长度(bit)对512求余的结果不等于448，就需要填充使得对512求余的结果等于448。填充的方法是填充一个1和n个0。填充完后，信息的长度就为N*512+448(bit)；

  (2) 记录信息长度：用64位来存储填充前信息长度。这64位加在第一步结果的后面，这样信息长度就变为512位。

  (3) 装入标准的幻数（四个整数）：标准的幻数（物理顺序）是（A=(01234567)16，B=(89ABCDEF)16，C=(FEDCBA98)16，D=(76543210)16）。如果在程序中定义应该是:
  （A=0X67452301L，B=0XEFCDAB89L，C=0X98BADCFEL，D=0X10325476L）。

  (4) 四轮循环运算：循环的次数是分组的个数（N+1）

#### 4.2 **公钥密码**&数字签名算法-RSA算法

+ **数字签名：** 

  PGP支持数字签名的生成和验证，也可以将数字签名附加到文件中，或者从文件中分离出数字签名。可以使用的数字签名算法包括RSA和DSA等。

+ **公钥密码：** 

  PGP支持生成公钥密码密钥对，以及用公钥密码进行加密和解密。可以使用的算法包括RSA和ElGamal等。

+ **RSA算法过程：**

  (1) 随机地选择两个大素数p和q，而且保密；

  (2) 计算n=pq，将n公开；

  (3) 计算φ(n)=(p-1)(q-1)，对φ(n)保密；

  (4) 随机地选取一个正整数e，1<e<φ(n)且(e,φ(n))=1，将e公开；

  (5) 根据ed=1(mod φ(n))，求出d，并对d保密；

  (6) 加密运算：c=m^e(mod n)； 

  (7) 解密运算：m=c^d(mod n)。

#### 4.3 对称密码-IDEA算法

+ **对称密码：**

  支持用对称密码进行加密和解密。对称密码可以单独使用，也可以和公钥密码组合成混合密码系统使用。 可以使用的对称密码算法包括AES、IDEA、CAST、3DES、Blowfish、Twofish等。

+ **IDEA算法过程：**

  IDEA是在DES算法的基础上发展出来的，是一个分组长度为 64 比特的分组密码算法，密钥长度为 128 比特，由 8 轮迭代操作实现。 每个迭代都由三种函数：mod（216）加法、mod（216+1）乘法和逐位异或算法组成。整个算法包括子密钥产生、数据加密过程、数据解密过程三部分。 该算法规定明文和密文块均为 64 比特，密钥长度为 128比特，加解密相同，只是密钥各异。

  IDEA 总共进行 8 轮迭代操作，每轮需要 6 个子密钥，另外还需要 4 个额外子密钥输出变换，所以总共需要 52 个子密钥，这 52 个子密钥都是从 128 比特密钥中扩展出来的。

#### 4.4 BASE64算法

+ **BASE64算法过程：**

  Base64是一种基于64个可打印字符来表示二进制数据的表示方法。由于![{\displaystyle \log _{2}64=6}](https://wikimedia.org/api/rest_v1/media/math/render/svg/9c986fbdc6c036a937e0647d7a6ec5ad745bccab)，所以每6个比特为一个单元，对应某个可打印字符。3个字节相当于24个比特，对应于4个Base64单元，即3个字节可由4个可打印字符来表示。它可用来作为电子邮件的传输编码。

  (1) 将待转换的字符串每三个字节分为一组，每个字节占8bit，那么共有24个二进制位。

  (2) 将上面的24个二进制位每6个一组，共分为4组。

  (3) 在每组前面添加两个0，每组由6个变为8个二进制位，总共32个二进制位，即四个字节。

  (4) 根据Base64编码对照表获得对应的值。

### 五、代码实现

#### 5.0 主函数和代码结构

代码结构

![](C:\Users\think\AppData\Roaming\Typora\typora-user-images\image-20201130184148200.png)

+ main.py 主函数

  + 生成随机的128位IDEA密钥
  + 生成1024位的服务端和客户端的RSA公钥和私钥
  + 调用服务端加密函数
  + 调用客户端解密函数

  ![image-20201130183549830](C:\Users\think\AppData\Roaming\Typora\typora-user-images\image-20201130183549830.png)

+ server.py 服务端加密

  将在5.1中详细介绍

+ client.py 客户端解密

  将在5.2中详细介绍

+ myMD5.py 自己实现的MD5函数

  这一部分的内容比较简单，只有一个生成文件的MD5值的函数

+ myRSA.py 自己实现的RSA函数

  这一部分包括生成RSA公钥私钥的函数，以及使用RSA加密/解密的函数

+ myIDEA.py 自己实现的IDEA函数

  这一部分包括IDEA的加密函数，解密函数和字符串和块之间相互转换的函数，这里我实现的ECB加密模式，即需要加密的消息按照块密码的块大小被分为数个块，并对每个块进行独立加密。

  ![Ecb encryption.png](https://upload.wikimedia.org/wikipedia/commons/c/c4/Ecb_encryption.png)

  ![Ecb decryption.png](https://upload.wikimedia.org/wikipedia/commons/6/66/Ecb_decryption.png)

+ ys168.com.txt 原始文件

+ ys168.com.txt.cypher 加密后的文件

+ ys168.com.txt.cypher.txt 解密后的文件

#### 5.1 加密过程

##### 5.1.1 邮件数据M经MD5进行压缩处理，形成数据的摘要。

使用自己写的myMD5库中的函数generate_MD5对邮件数据进行压缩处理，形成数据的摘要。

![image-20201129193104864](C:\Users\think\AppData\Roaming\Typora\typora-user-images\image-20201129193104864.png)

##### 5.1.2 用发送者的RSA私钥Kd对摘要进行数字签名，以确保真实性。

使用自己写的myRSA库中RSA加密的函数RSA_encrypt，用发送者的RSA私钥Kd对摘要进行数字签名。

![image-20201129193129421](C:\Users\think\AppData\Roaming\Typora\typora-user-images\image-20201129193129421.png)

##### 5.1.3 将邮件数据与数字签名拼接：数据在前，签名在后。

为了之后能将邮件数据与数字签名区分开，我在邮件数据前加标识字符“content=”，在签名前加标识字符“signature="，以便解密时将数据和签名区分开。

![image-20201129193412440](C:\Users\think\AppData\Roaming\Typora\typora-user-images\image-20201129193412440.png)

##### 5.1.4 用ZIP对拼接后的数据进行压缩，以便于存储和传输。

使用Python自带的zlib库，对前面生成的邮件数据与数字签名进行压缩

![image-20201129193753315](C:\Users\think\AppData\Roaming\Typora\typora-user-images\image-20201129193753315.png)

##### 5.1.5 用IDEA对压缩后的数据进行加密，加密钥为K，以确保秘密性。

首先进行格式转换，把上一步生成的二进制转为字符串，然后再通过string_to_blocks分块，接着依次对每个块进行IDEA加密

![image-20201129194148536](C:\Users\think\AppData\Roaming\Typora\typora-user-images\image-20201129194148536.png)

##### 5.1.6 用接受者的RSA公钥Ke加密IDEA的密钥K。

使用RSA_encrypt函数用接受者的RSA公钥对IDEA密钥K加密

![image-20201129194219935](C:\Users\think\AppData\Roaming\Typora\typora-user-images\image-20201129194219935.png)

##### 5.1.7 将经RSA加密的IDEA密钥与经IDEA加密的数据拼接:数据在前，密钥在后。

为了之后能将经RSA加密的IDEA密钥与经IDEA加密的数据拼接区分开，我在经IDEA加密的数据前加标识字符“data=”，在将经RSA加密的IDEA密钥的前面前加标识字符“signature="，以便解密时将数据和密钥区分开。

![image-20201129194246275](C:\Users\think\AppData\Roaming\Typora\typora-user-images\image-20201129194246275.png)

##### 5.1.8 将加密数据进行BASE 64变化，变化成ASCII码。因为许多E-mail系统只支持ASCII码数据。

使用python自带的base64加密函数加密数据

![image-20201129194303433](C:\Users\think\AppData\Roaming\Typora\typora-user-images\image-20201129194303433.png)

#### 5.2 解密过程

##### 5.2.1 将加密后的ASCII码进行BASE64解码，变成加密数据。

使用python自带的base64解密函数解密数据

![image-20201130175745721](C:\Users\think\AppData\Roaming\Typora\typora-user-images\image-20201130175745721.png)

##### 5.2.2 将加密数据中的经RSA加密的IDEA密钥与经IDEA加密的数据分开。

使用list中的split函数，以之前做的'data='为标记，遍历字符串，将第一个'data='后的数据分割下，再取分割后的字符串遍历，找到最后一个'key='分割，之前的为数据，之后的密钥。

![image-20201130175812966](C:\Users\think\AppData\Roaming\Typora\typora-user-images\image-20201130175812966.png)

![image-20201130212338991](C:\Users\think\AppData\Roaming\Typora\typora-user-images\image-20201130212338991.png)

##### 5.2.3 使用接受者的RSA私钥Kd解密IDEA的密钥K。

使用RSA_encrypt函数用接受者的RSA私钥对IDEA密钥K解密

![image-20201130175830834](C:\Users\think\AppData\Roaming\Typora\typora-user-images\image-20201130175830834.png)

##### 5.2.4 使用IDEA密钥K解密经IDEA加密的数据。

首先将字符串分块，还是适用ECB模式使用IDEA密钥K解密，接着将解密后的块变为整个字符串，最后再将字符串转为二进制数据

![image-20201130175902446](C:\Users\think\AppData\Roaming\Typora\typora-user-images\image-20201130175902446.png)

##### 5.2.5 将解密后的数据进行解压缩，以便于阅读。

使用Python自带的zlib库，对解密后的数据进行解压缩

![image-20201130175925141](C:\Users\think\AppData\Roaming\Typora\typora-user-images\image-20201130175925141.png)

##### 5.2.6 将邮件数据与数字签名分开，数据在前，签名在后。

与前面的思路类似，我使用list中的split函数，以之前做的'content='为标记，遍历字符串，将第一个'content='后的数据分割下，再取分割后的字符串遍历，找到最后一个'key='分割，之前的为数据，之后的密钥。

![image-20201130180005485](C:\Users\think\AppData\Roaming\Typora\typora-user-images\image-20201130180005485.png)

![image-20201130213653725](C:\Users\think\AppData\Roaming\Typora\typora-user-images\image-20201130213653725.png)

##### 5.2.7 用发送者的RSA公钥Ke对签名解密。

因为RSA的加密和解密是相同的步骤，所以依然适用RSA_encrypt函数用发送者的RSA公钥Ke对签名解密。

![image-20201130180030335](C:\Users\think\AppData\Roaming\Typora\typora-user-images\image-20201130180030335.png)

##### 5.2.8 对解密后的邮件数据进行MD5压缩，验证生成的数字签名与3.7中解密的签名是否相同。

使用自己写的myMD5库中的函数generate_MD5对邮件数据进行压缩处理，验证生成的数字签名与3.7中解密的签名是否相同并输出结果。

![image-20201130180224248](C:\Users\think\AppData\Roaming\Typora\typora-user-images\image-20201130180224248.png)

#### 5.3 运行截图

+ 加密过程截图：

![image-20201129223318660](C:\Users\think\AppData\Roaming\Typora\typora-user-images\image-20201129223318660.png)

可以看出时间主要花在IDEA加密上，因为IDEA加密需要经历二进制文件-字符串-分块-分块加密-分块-字符串的过程，所以花的时间较多。这也是接下来优化性能的主要方向。

+ 解密过程截图：

![image-20201130182915227](C:\Users\think\AppData\Roaming\Typora\typora-user-images\image-20201130182915227.png)

可以看出时间同样主要花在IDEA解密上，因为IDEA解密需要经历字符串-分块-分块解密-分块-字符串-二进制的过程，所以花的时间较多。但是验签结果是正确的，说明加密和解密算法是正确的。

+ 原始文件

  ![image-20201130202546760](C:\Users\think\AppData\Roaming\Typora\typora-user-images\image-20201130202546760.png)

+ 加密后的文件ys168.com.txt.cypher 

  ![image-20201130203023358](C:\Users\think\AppData\Roaming\Typora\typora-user-images\image-20201130203023358.png)

+ 解密后的文件 ys168.com.txt.cypher.txt 

  ![image-20201130210012007](C:\Users\think\AppData\Roaming\Typora\typora-user-images\image-20201130210012007.png)

#### 5.4 遇到的困难

##### 5.4.1 字符转换问题

![image-20201129184739590](C:\Users\think\AppData\Roaming\Typora\typora-user-images\image-20201129184739590.png)

最开始读入待加密的文件是以二进制方式读入的，进行到压缩后，文件就变成了一串无法解码的二进制编码，经过起那么几个步骤后，第4步结束后输出的结果为一串字符串，第5步使用python自带的zlib库，要求的输入为二进制字符。但是由于加密后的二进制编码是无法解码的，也就是说字符串是无法用python自带的bytes（msg, encoding = 'utf-8')这种方式解码的。经过很久的搜索资料和尝试后，我发现使用codecs这个库可以较好的解决我的问题。

代码如下：

```python
msg = bytes(msg[2:-1], encoding = 'utf-8')
original = codecs.escape_decode(msg, 'hex-escape')
```



##### 5.4.2 大字符串加法运算速度慢问题

![image-20201130215211784](C:\Users\think\AppData\Roaming\Typora\typora-user-images\image-20201130215211784.png)

在第4步的IDEA加密过程中，需要进行二进制文件-字符串-分块-分块加密-分块-字符串的过程，我首先想到的是对字符串做加法，具体见下面的代码：

```
msg = ''
for m in encrypt_IDEA_words:
	msg = msg + str(m)
```

但是测速后发现速度很慢，字符串越大在它后面的加字符串的时间就越长，因为我们的文件有10MB左右，所以运行到后面的时间是我们不能接受的。经过查阅资料，发现还有一种方法使用先list.append再''.join的方法，避免了上述情况的出现，显著提高了效率（90%+）。

```
l = []
    for m in encrypt_IDEA_words:
        l.append(str(m))
    msg += ''.join(l)
```

