import random
from math import gcd
from sympy import mod_inverse

#素性检验
def is_prime(n):
    """判断一个数是否为素数"""
    if n <= 1:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    for i in range(3, int(n ** 0.5) + 1, 2):
        if n % i == 0:
            return False
    return True

#生成大素数
def generate_large_prime(bits=16):
    """生成一个大素数"""
    while True:
        num = random.getrandbits(bits)
        if is_prime(num):
            return num

# 生成RSA密钥对
def generate_rsa_keys(bits=16):
    while True:
        p = generate_large_prime(bits)
        q = generate_large_prime(bits)
        while p == q:
            q = generate_large_prime(bits)
        n = p * q
        phi_n = (p - 1) * (q - 1)
        e = 3
        if gcd(e, phi_n) == 1:
            break
    d = mod_inverse(e, phi_n)
    return (e, n), (d, n)

# 加密函数
def encrypt(m, pub_key):
    e, n = pub_key
    encrypted = [pow(ord(char), e, n) for char in m]
    return encrypted

# 解密函数
def decrypt(c, priv_key):
    d, n = priv_key
    decrypted = ''.join(chr(pow(char, d, n)) for char in c)
    return decrypted

# 测试
def rsa_test():
    pub_key, priv_key = generate_rsa_keys(bits=16)
    print("Public key:", pub_key)
    print("Private key:", priv_key)
    message = "Hello, RSA!"
    # 加密消息
    encrypted_message = encrypt(message, pub_key)
    print("Ciphertext:", encrypted_message)
    # 解密消息
    decrypted_message = decrypt(encrypted_message, priv_key)
    print("Plaintext:", decrypted_message)

# 测试
rsa_test()
