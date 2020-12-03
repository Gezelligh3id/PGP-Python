import myMD5
import myRSA
import myIDEA
import zipfile
import zlib
import base64
import time
def server(msg_file, IDEA_key, client_e, client_n, server_d, server_n, decrypt_file):
    begin_time = time.time()
    print("===========================================PGP算法加密部分开始==========================================")
    print("----------------------------------------Step 0:选择要加密的文件----------------------------------------")
    print("待加密的文件为:", msg_file)

    # 生成文件的MD5值
    print("----------------------------------------Step 1:生成文件的MD5值----------------------------------------")
    md5_val = myMD5.generate_MD5(msg_file)
    print("文件的MD5值为:", md5_val)
    time_1 = time.time()
    print('时间为:{:.2f}s'.format(time_1-begin_time))

    # 生成签名
    print("------------------------------------------Step 2:生成文件签名-----------------------------------------")
    m = int(md5_val, 16)
    signature = myRSA.RSA_encrypt(m, server_d, server_n)
    print("生成文件签名完成!!!!!")
    time_2 = time.time()
    print('时间为:{:.2f}s'.format(time_2 - time_1))

    # 将邮件数据与数字签名拼接
    print("-------------------------------------Step 3:将邮件数据与数字签名拼接-------------------------------------")
    with open(msg_file, "rb") as f:
        raw_data = f.read()
    data = 'content=' + str(raw_data) + 'signature=' + str(signature)
    print("邮件数据与数字签名拼接完成!!!!!")
    time_3 = time.time()
    print('时间为:{:.2f}s'.format(time_3 - time_2))

    # 压缩文件
    print("--------------------------------------------Step 4:压缩文件-------------------------------------------")
    compress_data = zlib.compress(str.encode(data), zlib.Z_BEST_COMPRESSION)
    print("文件压缩完成!!!!!")
    time_4 = time.time()
    print('时间为:{:.2f}s'.format(time_4 - time_3))

    # IDEA对压缩后的数据进行加密
    print("------------------------------------Step 5:IDEA对压缩后的数据进行加密------------------------------------")
    my_idea = myIDEA.IDEA(key=IDEA_key)
    blocks = myIDEA.string_to_blocks(str(compress_data))
    encrypt_IDEA_words = []
    for block in blocks:
        encrypt_IDEA_words.append(my_idea.encrypt(block))
    print("文件使用IDEA加密完成!!!!!")
    time_5 = time.time()
    print('时间为:{:.2f}s'.format(time_5 - time_4))

    # RSA加密IDEA密钥
    print("--------------------------------------Step 6:使用RSA加密IDEA密钥--------------------------------------")
    encrypt_IDEA_key = myRSA.RSA_encrypt(IDEA_key, client_e, client_n)
    print("使用RSA加密IDEA密钥完成!!!!!")
    time_6 = time.time()
    print('时间为:{:.2f}s'.format(time_6 - time_5))

    # 密钥和数据拼接，数据在前
    print("----------------------------Step 7:将RSA加密后的IDEA密钥与IDEA加密后的数据拼接----------------------------")
    msg = 'data='
    l = []
    for m in encrypt_IDEA_words:
        l.append(str(m))
        l.append(',')
    msg += ''.join(l)
    # for m in encrypt_IDEA_words:
    #     msg = msg + str(m) + ','
    msg = msg + 'key=' + str(encrypt_IDEA_key)
    print("将RSA加密后的IDEA密钥与IDEA加密后的数据拼接完成!!!!!")
    time_7 = time.time()
    print('时间为:{:.2f}s'.format(time_7 - time_6))

    print("------------------------------------Step 8:将加密数据进行BASE64加密------------------------------------")
    base64_encode_data = base64.b64encode(msg.encode('utf-8'))
    print("将加密数据进行BASE64加密完成!!!!!")
    time_8 = time.time()
    print('时间为:{:.2f}s'.format(time_8 - time_7))

    with open(decrypt_file, 'wb') as f:
        f.write(base64_encode_data)
    print("加密后的文件为:", decrypt_file)
    print('总加密时间为:{:.2f}s'.format(time_8 - begin_time))
    print("===========================================PGP算法加密部分结束==========================================")
