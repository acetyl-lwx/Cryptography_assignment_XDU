import base64
import os
import Crypto.Cipher.AES as AES
import string
 
# 添加padding
def pad(message:bytes, block_size:int) -> bytes:
    padding = block_size - len(message) % block_size
    return message + bytes([padding] * padding)

#去除padding
def unpad(message:bytes) -> bytes:
    padding = message[-1]
    return message[:-padding]

#加密函数
def AES_ECB_encrpt(control_text:bytes):
    key = os.urandom(16)
    plaintext = pad(control_text + base64.b64decode("""
Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK"""), 16)
    return AES.new(key, AES.MODE_ECB).encrypt(plaintext)

#枚举得到明文长度
init_unk_strlen = len(AES_ECB_encrpt(b""))
unk_strlen = init_unk_strlen
for i in range(16):
    if len(AES_ECB_encrpt(b"A" * i)) != init_unk_strlen:
        unk_strlen = init_unk_strlen - i
        break

#DFS得到明文
plain_space = string.printable.encode()
def dfs(known_text: bytes):
    while True:
        partial = known_text[-15:]
        partial = b"\x00" * (15 - len(partial)) + partial
        current = []
        for i in plain_space:
            oracle = partial + bytes([i]) + b"\x00" * (15 - len(known_text) % 16)
            enc = AES_ECB_encrpt(oracle)
            if enc[15] == enc[len(known_text) // 16 * 16 + 31]:
                current.append(i)
        if len(current) == 1:
            known_text += bytes(current)
            if len(known_text) == unk_strlen: # 达到预期长度，成功退出
                print(known_text.decode())
                return True
            continue
        elif len(current) == 0:
            return False
        else:
            for c in current:
                if dfs(known_text + bytes([c])):
                    return True
dfs(b'')