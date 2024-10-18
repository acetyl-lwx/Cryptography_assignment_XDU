from Crypto.Cipher import AES
from Crypto import Random

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

#profile
def profile_for(email):
    email=email.replace('&','').replace('=','')
    return {'email':email, 'uid':10, 'role':'user'}

#字典转字符串
def kv_encode(dict_object):
    encode_text=''
    for item in dict_object.items():
        encode_text += item[0] + '=' + str(item[1]) + '&'
    return encode_text[:-1]

#字符串转字典
def kv_decode(encode_text):
    dict_object={}
    attributes=encode_text.split('&')
    for item in attributes:
        dict_object[item.split('=')[0]]=item.split('=')[1]
    return dict_object

#ECB模式加解密
class ECBoracle:
    def __init__(self):
        self.key=Random.new().read(AES.key_size[0])
    def encrypt(self, email):
        encoded=kv_encode(profile_for(email))
        bytes_to_encrypted=encoded.encode()
        return AES_ECB_encrypt(bytes_to_encrypted, self.key)
    def decrypt(self, ciphertext):
        return unpad(AES_ECB_decrypt(ciphertext, self.key))
    
#cut and paste攻击
def cut_and_paste_attack(oracle):
    prefix_len = AES.block_size - len('email=')
    suffix_len = AES.block_size - len('admin')
    email1 = 'x' * prefix_len + 'admin' + (chr(suffix_len)*suffix_len)
    encrypt1 = oracle.encrypt(email1)
    email2 = "master@xd.com"
    encrypt2 = oracle.encrypt(email2)
    ciphertext = encrypt2[:32] + encrypt1[16:32]
    return ciphertext

oracle=ECBoracle()
ciphertext=cut_and_paste_attack(oracle)
decrypt = oracle.decrypt(ciphertext).decode()
plaintext = kv_decode(decrypt)
print(plaintext)