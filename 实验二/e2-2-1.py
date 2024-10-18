# 添加padding
def pad(message:bytes, block_size:int) -> bytes:
    padding = block_size - len(message) % block_size
    return message + bytes([padding] * padding)

#去除padding
def unpad(message:bytes) -> bytes:
    padding = message[-1]
    return message[:-padding]

message_pading = pad(b'YELLOW SUBMARINE', 16)
print(message_pading)
print(unpad(message_pading))
