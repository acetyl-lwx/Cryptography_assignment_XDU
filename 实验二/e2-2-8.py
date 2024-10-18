import Crypto.Cipher.AES as AES
import os

key = os.urandom(16) 

# 填充
def pad(message: bytes, block_size: int) -> bytes:
    padding = block_size - len(message) % block_size
    return message + bytes([padding] * padding)
 
# 去除填充
def unpad(message_padded):
    padding_len = message_padded[-1]
    message, padding = message_padded[:-padding_len], message_padded[-padding_len:]
    assert all(x == padding_len for x in padding)
    return message

# CBC模式加密
def AES_CBC_encrypt(userdata: bytes):
    data = (
        b"comment1=cooking MCs;userdata="
        + userdata.replace(b";", b"%3B").replace(b"=", b"%3D")
        + b";comment2= like a pound of bacon"
    )
    return AES.new(key, AES.MODE_CBC, os.urandom(16)).encrypt(pad((b"\x00" * 16) + data, 16))
 
# CBC模式解密
def AES_CBC_decrypt(data: bytes):
    data = unpad(AES.new(key, AES.MODE_CBC, os.urandom(16)).decrypt(data))[16:]
    return {
        (kv := item.split(b"=", maxsplit=1))[0].decode(): kv[1]
        for item in data.split(b";")
    }
 
# 检测函数
def is_admin(data: bytes):
    decrypted = AES_CBC_decrypt(data)
    return decrypted.get("admin") == b"true"

padlen = 2
userdata = b"A" * padlen + b":admin<true"
enc = bytearray(AES_CBC_encrypt(userdata))
enc[padlen + 30] ^= ord(":") ^ ord(";")
enc[padlen + 36] ^= ord("<") ^ ord("=")
if is_admin(enc):
    print("Success!")
else:
    print("Fail!")