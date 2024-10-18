import base64
import os
import Crypto.Cipher.AES as AES
import string
import random

# 先生成随机长度，随机生成的前缀
prefix_len = random.randint(0, 64)
prefix = os.urandom(prefix_len)

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
    plaintext = pad(prefix + control_text + base64.b64decode("""
Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK"""), 16)
    return AES.new(key, AES.MODE_ECB).encrypt(plaintext)

#枚举得到明文长度,前缀导致的偏移量和需要的补齐长度
def get_unklen():
    init_unk_strlen = len(AES_ECB_encrpt(b""))
    unk_strlen = init_unk_strlen
    for i in range(16):
        if len(AES_ECB_encrpt(b"A" * i)) != init_unk_strlen:
            unk_strlen = init_unk_strlen - i
            break
    leftlen = 0
    while True:
        leftlen += 1
        enc = AES_ECB_encrpt(b"A" * leftlen)
        blocks = [enc[i : i + 16] for i in range(0, len(enc), 16)]
        for i in range(len(blocks) - 1):
            if blocks[i] == blocks[i + 1]:
                return unk_strlen - i * 16 + leftlen % 16, i * 16, leftlen % 16
 
unk_strlen, offset, leftpad = get_unklen()
leftpad = b"\x00" * leftpad

#DFS得到明文
plain_space = string.printable.encode()
 
 
def dfs(known_text):
    while True:
        partial = known_text[-15:]
        partial = b"\x00" * (15 - len(partial)) + partial
        current = []
        for i in plain_space:
            oracle = leftpad + partial + bytes([i]) + b"\x00" * (15 - len(known_text) % 16)
            enc = AES_ECB_encrpt(oracle)[offset:]
            if enc[15] == enc[len(known_text) // 16 * 16 + 31]:
                current.append(i)
        if len(current) == 1:
            known_text += bytes(current)
            if len(known_text) == unk_strlen:
                print(known_text.decode())
                return True
            continue
        elif len(current) == 0:
            return False
        else:
            for c in current:
                if dfs(known_text + bytes([c])):
                    return True
dfs(b"")