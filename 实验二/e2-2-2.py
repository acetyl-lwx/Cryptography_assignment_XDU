from Crypto.Cipher import AES
from base64 import b64decode

# 添加padding
def pad(message:bytes, block_size:int) -> bytes:
    padding = block_size - len(message) % block_size
    return message + bytes([padding] * padding)

#去除padding
def unpad(message:bytes) -> bytes:
    padding = message[-1]
    return message[:-padding]

# AES ECB模式加密
def AES_ECB_encrypt(plaintext: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(plaintext, AES.block_size))

#AES ECB模式解密
def AES_ECB_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(ciphertext)

#异或
def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

#AES CBC模式加密
def AES_CBC_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    cipher=b''
    prev=iv
    plaintext=pad(plaintext, AES.block_size)
    for i in range(0, len(plaintext), AES.block_size):
        current_plaintext_block = plaintext[i:i + AES.block_size]
        block_cipher_input=xor(current_plaintext_block, prev)
        block_cipher_output=AES_ECB_encrypt(block_cipher_input, key)
        cipher+=block_cipher_output
        prev=block_cipher_output
    return cipher

#AES CBC模式解密
def AES_CBC_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    plaintext=b''
    prev=iv
    for i in range(0, len(ciphertext), AES.block_size):
        current_ciphertext_block = ciphertext[i:i + AES.block_size]
        block_plaintext_input=AES_ECB_decrypt(current_ciphertext_block, key)
        block_plaintext_output=xor(block_plaintext_input, prev)
        plaintext+=block_plaintext_output
        prev=current_ciphertext_block
    return plaintext

iv=b'\x00'* AES.block_size
key=b'YELLOW SUBMARINE'
with open('10.txt') as plaintext_file:
    plaintext=b64decode(plaintext_file.read())
print(AES_CBC_decrypt(plaintext, key, iv).decode().rstrip())



