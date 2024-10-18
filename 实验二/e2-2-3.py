import os
import random
import Crypto.Cipher.AES as AES

#随机密钥 
def random_key():
    return os.urandom(16)

#随机前后缀
def random_padding():
    return os.urandom(random.randint(5, 10))

def pad(message:bytes, block_size:int) -> bytes:
    padding = block_size - len(message) % block_size
    return message + bytes([padding] * padding)

#去除padding
def unpad(message:bytes) -> bytes:
    padding = message[-1]
    return message[:-padding]

#选择加密机
def encryption_oracle(key, message):
    mode = random.choice([AES.MODE_ECB, AES.MODE_CBC])
    plaintext = random_padding() + message + random_padding()
    plaintext = pad(plaintext, 16)
    match mode:
        case AES.MODE_ECB:
            return AES.new(key, mode).encrypt(plaintext), mode
        case AES.MODE_CBC:
            iv = random_key()
            return AES.new(key, mode, iv).encrypt(plaintext), mode
    assert False, "unreachable"

#检测预言机
def detect_mode_oracle(ciphertext):
    blocks = [ciphertext[i : i + 16] for i in range(0, len(ciphertext), 16)]
    if len(blocks) != len(set(blocks)):
        return AES.MODE_ECB
    return AES.MODE_CBC

key = random_key()
msg = b"\x00" * 16 * 3
encrypted = [encryption_oracle(key, msg) for _ in range(1000)]
accr = sum(detect_mode_oracle(ciphertext) == mode for ciphertext, mode in encrypted)
print(f"{accr / len(encrypted):.2%}")

