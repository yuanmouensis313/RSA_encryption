# rsa生成密钥
import math
from random import randint


def charToAscii(message):  # 将字符转化为ASCII码
    Output = []
    for i in message:
        Output.append(ord(i))
    return Output


def AsciiToHex(message):  # 将ASCII码转化为16进制
    Output = ''
    for each in message:
        Output = Output + str(hex(each)).split('x')[1]
    return Output


def Hex_to_dec(hexnumber):  # 16进制字符串转化为十进制
    decnumber = int(hexnumber, 16)
    return decnumber


def dec_to_Hex(decumber):  # 十进制转化为十六进制
    hexnumber = hex(decumber)
    return hexnumber


def rsa_key():
    # 生成p、q两个大素数
    p = randint(10000000000
                , 10000000000000000000)
    while not is_prime(p):
        p = randint(10000000000
                    , 10000000000000000000)
    q = randint(10000000000
                , 10000000000000000000)
    while not is_prime(q):
        q = randint(10000000000
                    , 10000000000000000000)
    # 计算n
    n = p * q
    # 计算欧拉函数
    f = (p - 1) * (q - 1)
    # 随机选择一个整数e，条件是1< e < f，且e与f互质
    e = randint(1, f)
    while not is_prime(e):
        e = randint(1, f)
    # 利用扩展欧几里得算法，求出e关于f的模反元素d
    d = ex_gcd(e, f)[0]
    # 返回：公钥（n，e），私钥（n，d）
    return (n, e), (n, d)


# 判断素数
def is_prime(num):
    if num <= 1:
        return False
    for i in range(2, int(math.sqrt(num) + 1)):
        if num % i == 0:
            return False
    return True


# 扩展欧几里得算法
def ex_gcd(a, b):
    if b == 0:
        return 1, 0, a
    else:
        x, y, q = ex_gcd(b, a % b)
        x, y = y, (x - (a // b) * y)
        return x, y, q


# rsa加密
def rsa_encrypt(message, public_key):
    # 获取公钥
    n = public_key[0][0]
    e = public_key[0][1]
    # # 将明文转化为ASCII码
    # message = charToAscii(message)
    # # 将明文转化为16进制
    # message = AsciiToHex(message)
    # 将16进制转化为10进制
    message = Hex_to_dec(message)
    # 加密
    message = pow(message, e, n)
    # 将加密后的密文转化为16进制
    message = dec_to_Hex(message)
    # # 将16进制转化为ASCII码
    # message = int(message.split('x')[1], 16)
    # # 将ASCII码转化为明文
    # message = chr(message)
    return message


# rsa解密
def rsa_decrypt(message, private_key):
    # 获取私钥
    n = private_key[1][0]
    d = private_key[1][1]
    # # 将密文转化为ASCII码
    # message = charToAscii(message)
    # # 将密文转化为16进制
    # message = AsciiToHex(message)
    # 将16进制转化为10进制
    message = Hex_to_dec(message)
    # 解密
    message = pow(message, d, n)
    # 将解密后的明文转化为16进制
    message = dec_to_Hex(message)
    # # 将16进制转化为ASCII码
    # message = message.split('x')[1]
    # # 将ASCII码转化为明文
    # message = message.encode('utf-8').decode()
    return message


# 数字签名
def rsa_sign(message, private_key):
    # 获取私钥
    n = private_key[0]
    d = private_key[1]
    # 将明文转化为ASCII码
    message = charToAscii(message)
    # 将明文转化为16进制
    message = AsciiToHex(message)
    # 将16进制转化为10进制
    message = Hex_to_dec(message)
    # 加密
    message = pow(message, d, n)  # d为私钥，n为公钥
    # 将加密后的密文转化为16进制
    message = dec_to_Hex(message)
    # 将16进制转化为ASCII码
    message = message.split('x')[1]
    # 将ASCII码转化为明文
    message = message.encode('utf-8').decode('hex')
    return message


if __name__ == "__main__":
    key = rsa_key()
    plain = '63727970746F677261706879'
    encryption = ''
    encryption = encryption + rsa_encrypt(plain, key)
    print('RSA加密:' + encryption)

    decryption = ''
    decryption = decryption + rsa_decrypt(encryption, key)

    print('RSA解密:' + decryption)
