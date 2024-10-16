import base64
import itertools

# 字母频率表
letter_frequency = {
    'a': 0.0651738, 'b': 0.0124248, 'c': 0.0217339,
    'd': 0.0349835, 'e': 0.1041442, 'f': 0.0197881,
    'g': 0.0158610, 'h': 0.0492888, 'i': 0.0558094,
    'j': 0.0009033, 'k': 0.0050529, 'l': 0.0331490,
    'm': 0.0202124, 'n': 0.0564513, 'o': 0.0596302,
    'p': 0.0137645, 'q': 0.0008606, 'r': 0.0497563,
    's': 0.0515760, 't': 0.0729357, 'u': 0.0225134,
    'v': 0.0082903, 'w': 0.0171272, 'x': 0.0013692,
    'y': 0.0145984, 'z': 0.0007836, ' ': 0.1918182
}

# 计算文本频率分
def calculate_text_score(byte_array):
    score = 0
    for byte in byte_array:
        score += letter_frequency.get(chr(byte).lower(), 0)
    return score

# 异或
def xor_with_single_char(byte_array, key_byte):
    result = b''
    for byte in byte_array:
        result += bytes([byte ^ key_byte])
    return result

# 用字频法破解单字节加密的密文
def brute_force_single_char_xor(ciphertext):
    results = []
    for key in range(256):
        plaintext = xor_with_single_char(ciphertext, key)
        score = calculate_text_score(plaintext)
        results.append({
            'key': key,
            'score': score,
            'plaintext': plaintext
        })
    return sorted(results, key=lambda x: x['score'], reverse=True)[0]

# 字符串与重复密钥异或
def xor_with_repeating_key(byte_array, key):
    result = b''
    key_length = len(key)
    for i, byte in enumerate(byte_array):
        result += bytes([byte ^ key[i % key_length]])
    return result

# 计算两个字符串的hamming距离
def compute_hamming_distance(string1, string2):
    assert len(string1) == len(string2)
    distance = 0
    for byte1, byte2 in zip(string1, string2):
        xor_result = byte1 ^ byte2
        distance += bin(xor_result).count('1')
    return distance

def break_repeating_key_xor(ciphertext):
    key_size_distances = {}
    for key_size in range(2, 41):
        chunks = [ciphertext[i:i + key_size] for i in range(0, len(ciphertext), key_size)][:4]
        total_distance = 0
        pairs = itertools.combinations(chunks, 2)
        for chunk1, chunk2 in pairs:
            total_distance += compute_hamming_distance(chunk1, chunk2)
        average_distance = total_distance / 6
        normalized_distance = average_distance / key_size
        key_size_distances[key_size] = normalized_distance
    
    best_key_sizes = sorted(key_size_distances, key=key_size_distances.get)[:3]
    print(best_key_sizes)

    decrypted_plaintexts = []
    for size in best_key_sizes:
        key = b''
        for i in range(size):
            block = b''
            for j in range(i, len(ciphertext), size):
                block += bytes([ciphertext[j]])
            key += bytes([brute_force_single_char_xor(block)['key']])
        decrypted_plaintexts.append((xor_with_repeating_key(ciphertext, key), key))
    
    return max(decrypted_plaintexts, key=lambda x: calculate_text_score(x[0]))

#解密
with open("ciphertext.txt") as file:
    encoded_data = base64.b64decode(file.read())
decrypted_result = break_repeating_key_xor(encoded_data)
print("The Key is", decrypted_result[1].decode())
print("The Length is", len(decrypted_result[1].decode()))
print(decrypted_result[0].decode().rstrip())

