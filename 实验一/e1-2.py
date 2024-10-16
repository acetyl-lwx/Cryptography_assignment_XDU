import string

ciphertext = 'F96DE8C227A259C87EE1DA2AED57C93FE5DA36ED4EC87EF2C63AAE5B9A\
7EFFD673BE4ACF7BE8923CAB1ECE7AF2DA3DA44FCF7AE29235A24C963FF0DF3CA3599A\
70E5DA36BF1ECE77F8DC34BE129A6CF4D126BF5B9A7CFEDF3EB850D37CF0C63AA2509A\
76FF9227A55B9A6FE3D720A850D97AB1DD35ED5FCE6BF0D138A84CC931B1F121B44ECE\
70F6C032BD56C33FF9D320ED5CDF7AFF9226BE5BDE3FF7DD21ED56CF71F5C036A94D96\
3FF8D473A351CE3FE5DA3CB84DDB71F5C17FED51DC3FE8D732BF4D963FF3C727ED4AC8\
7EF5DB27A451D47EFD9230BF47CA6BFEC12ABE4ADF72E29224A84CDF3FF5D720A459D4\
7AF59232A35A9A7AE7D33FB85FCE7AF5923AA31EDB3FF7D33ABF52C33FF0D673A551D9\
3FFCD33DA35BC831B1F43CBF1EDF67F0DF23A15B963FE5DA36ED68D378F4DC36BF5B9A\
7AFFD121B44ECE76FEDC73BE5DD27AFCD773BA5FC93FE5DA3CB859D26BB1C63CED5CDF\
3FE2D730B84CDF3FF7DD21ED5ADF7CF0D636BE1EDB79E5D721ED57CE3FE6D320ED57D4\
69F4DC27A85A963FF3C727ED49DF3FFFDD24ED55D470E69E73AC50DE3FE5DA3ABE1EDF\
67F4C030A44DDF3FF5D73EA250C96BE3D327A84D963FE5DA32B91ED36BB1D132A31ED8\
7AB1D021A255DF71B1C436BF479A7AF0C13AA14794'

#将十六进制字母转为十进制数字，便于计算
def hex_to_ascii(hex_text):
    ascii_list = []
    for i in range(0, len(hex_text), 2):
        ascii_list.append(int(hex_text[i:i + 2], 16))
    return ascii_list

#枚举所有key值，根据明文是否合法，确定key值
def find_possible_keys(byte_group):
    valid_chars = string.ascii_letters + ',' + '.' + ' '
    potential_keys = []
    confirmed_keys = []
    for i in range(0x00, 0xFF):
        potential_keys.append(i)
        confirmed_keys.append(i)
    for key in potential_keys:
        for byte in byte_group:
            if chr(key ^ byte) not in valid_chars:
                confirmed_keys.remove(key)
                break
    return confirmed_keys

#枚举得key长度和key值
cipher_bytes = hex_to_ascii(ciphertext)
actual_key_length = 0
vigenere_like_keys = []
for length in range(1, 14):
    temp_keys = []
    for index in range(0, length):
        byte_group = cipher_bytes[index::length]
        keys = find_possible_keys(byte_group)
        if not keys:
            break
        else:
            temp_keys.insert(index, keys)
    if temp_keys:
        actual_key_length = length
        vigenere_like_keys = temp_keys
        print(length)
        print(f"key:{temp_keys}")

#得到明文
decrypted_text = ''
for i in range(0, len(cipher_bytes)):
    decrypted_text = decrypted_text + chr(cipher_bytes[i] ^ vigenere_like_keys[i % actual_key_length][0])
print(decrypted_text)
