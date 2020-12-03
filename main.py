from client import *
from server import *
import random
from myRSA import *
if __name__ == '__main__':
    # 随机生成IDEA密钥
    IDEA_key = random.getrandbits(128)

    # 生成1024位的服务端和客户端RSA公钥和私钥
    server_p, server_q, server_n, server_e, server_d = generate_RSA_key()
    client_p, client_q, client_n, client_e, client_d = generate_RSA_key()

    # 原始文件
    source_file = 'ys168.com.txt'
    # 加密后的文件
    encrypt_file = 'ys168.com.txt.cypher'
    # 解密后的文件
    decrypt_file = 'ys168.com.txt.cypher.txt'
    # 服务端加密
    server(source_file, IDEA_key, client_e, client_n, server_d, server_n, encrypt_file)
    # 客户端解密
    client(encrypt_file, client_n, client_d, server_e, server_n, decrypt_file)