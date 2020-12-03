import base64
import myRSA
import myIDEA
import myMD5
import zlib
import codecs
import time
from pywin32_testutil import str2bytes
def IDEA_data_process(msg):
    msg = str(msg)
    str_data = msg.split("data=")[1]
    data, key = str_data.split('key=')[0], msg.split('key=')[1][:-1]
    return data, key

def data_process(msg):
    msg = str(msg)
    tmp = msg.split('content=', 1)[1]
    content, signature = tmp.rsplit('signature=', 1)[0], tmp.rsplit('signature=', 1)[1][:-1]
    return content, signature

def client(encrypt_file, client_n, client_d, server_e, server_n, decrypt_file):
    begin_time = time.time()
    print("===========================================PGP算法解密部分开始==========================================")
    print("----------------------------------------Step 0:选择要解密的文件----------------------------------------")
    print("待加密的文件为:", encrypt_file)

    # 将加密后的ASCII码进行BASE64解码
    print("--------------------------------------Step 1:对文件进行BASE64解码--------------------------------------")
    with open(encrypt_file, 'r') as f:
        msg = f.read()
    msg = base64.b64decode(msg)
    print("BASE64解码完成!!!!!")
    time_1 = time.time()
    print('时间为:{:.2f}s'.format(time_1-begin_time))

    # 将加密数据中的经RSA加密的IDEA密钥与经IDEA加密的数据分开
    print("--------------------------------------Step 2:将IDEA密钥与数据分开--------------------------------------")
    encrypt_IDEA_data, encrypt_IDEA_key = IDEA_data_process(msg)
    print("将加密数据中的经RSA加密的IDEA密钥与经IDEA加密的数据分开完成!!!!!")
    time_2 = time.time()
    print('时间为:{:.2f}s'.format(time_2 - time_1))

    # 使用接受者的RSA私钥Kd解密IDEA的密钥K
    print("-------------------------------Step 3:使用接受者的RSA私钥Kd解密IDEA的密钥K-------------------------------")
    decrypt_IDEA_key = myRSA.RSA_encrypt(int(encrypt_IDEA_key), client_d, client_n)
    print("IDEA密钥K为:", hex(decrypt_IDEA_key))
    time_3 = time.time()
    print('时间为:{:.2f}s'.format(time_3 - time_2))

    # 使用IDEA密钥K解密经IDEA加密的数据
    print("--------------------------------Step 4:使用IDEA密钥K解密经IDEA加密的数据---------------------------------")
    blocks = encrypt_IDEA_data.split(',')[:-1]
    my_idea = myIDEA.IDEA(key=decrypt_IDEA_key)
    decrypt_IDEA_words = []
    for block in blocks:
        decrypt_IDEA_words.append(my_idea.decrypt(int(block)))
    msg = myIDEA.blocks_to_string(decrypt_IDEA_words)
    msg = bytes(msg[2:-1], encoding = 'utf-8')
    original = codecs.escape_decode(msg, 'hex-escape')
    print("使用IDEA密钥K解密经IDEA加密的数据完成!!!!!")
    time_4 = time.time()
    print('时间为:{:.2f}s'.format(time_4 - time_3))

    # 将解密后的数据进行解压缩
    print("------------------------------------Step 5:将解密后的数据进行解压缩-------------------------------------")
    uncompress_data = zlib.decompress(original[0])
    print("将解密后的数据进行解压缩完成!!!!!")
    time_5 = time.time()
    print('时间为:{:.2f}s'.format(time_5 - time_4))

    # 将邮件数据与数字签名分开，数据在前，签名在后
    print("------------------------------------Step 6:将邮件数据与数字签名分开-------------------------------------")
    content, signature = data_process(uncompress_data)
    content = bytes(content[2:-1], encoding = 'utf-8')
    print("将邮件数据与数字签名分开完成!!!!!")
    time_6 = time.time()
    print('时间为:{:.2f}s'.format(time_6 - time_5))

    # 用发送者的RSA公钥Ke对签名解密
    print("----------------------------------Step 7:用发送者的RSA公钥Ke对签名解密-----------------------------------")
    signature_decrypt = myRSA.RSA_encrypt(int(signature), server_e, server_n)
    print("解密后的签名为:", hex(signature_decrypt))
    time_7 = time.time()
    print('时间为:{:.2f}s'.format(time_7 - time_6))

    # 验证解密后的文件生成的数字签名是否相同
    print("-------------------------------Step 8:验证解密后的文件生成的数字签名是否相同--------------------------------")
    with open(decrypt_file, 'wb') as f:
        f.write(content)
    md5_val = myMD5.generate_MD5(decrypt_file)
    print("文件的MD5值为:", hex(md5_val))
    if md5_val == signature_decrypt:
        print('验签成功!!!!!')
    else:
        print('验签失败!!!!!')
    time_8 = time.time()
    print('时间为:{:.2f}s'.format(time_8 - time_7))

    print("解密后的文件为:", decrypt_file)
    print('总解密时间为:{:.2f}s'.format(time_8 - begin_time))
    print("===========================================PGP算法解密部分结束==========================================")