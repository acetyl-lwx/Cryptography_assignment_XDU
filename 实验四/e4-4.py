#扩展欧几里得算法 
def ext_gcd(a, b):    
    if b == 0:          
        return 1, 0, a     
    else:         
        x, y, gcd = ext_gcd(b, a % b)      
        x, y = y, (x - (a // b) * y)       
        return x, y, gcd

def hex_to_char(hex_str):
    return bytes.fromhex(hex_str).decode('utf-8')

with open("Frame0") as file:
    message=file.read()
    n_1=int(message[:256],16)
    e_1=int(message[256:512],16)
    c_1=int(message[512:],16)
file.close()
with open("Frame4") as file:
    message=file.read()
    n_2=int(message[:256],16)
    e_2=int(message[256:512],16)
    c_2=int(message[512:],16)
file.close()

x,y,g=ext_gcd(e_1,e_2)
plaintext=pow(c_1,x,n_1)*pow(c_2,y,n_2)
plaintext=plaintext%n_1
print(hex(plaintext))
print(hex_to_char(hex(plaintext)[-16:]))
