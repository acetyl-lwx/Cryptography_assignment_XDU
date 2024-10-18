def pad(message: bytes, block_size: int) -> bytes:
    padding = block_size - len(message) % block_size
    return message + bytes([padding] * padding)
 
def unpad(message_padded):
    padding_len = message_padded[-1]
    message, padding = message_padded[:-padding_len], message_padded[-padding_len:]
    assert all(x == padding_len for x in padding)
    return message

print(unpad(b"ICE ICE BABY\x04\x04\x04\x04"))
print(unpad(b"ICE ICE BABY\x05\x05\x05\x05"))