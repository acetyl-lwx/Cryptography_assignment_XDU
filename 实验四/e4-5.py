import gmpy2
def gcd(a, b):
    if b == 0:
        return a
    else:
        return gcd(b, a % b)

def hex_to_char(hex_str):
    return bytes.fromhex(hex_str).decode('utf-8')

with open("Frame1") as file:
    message=file.read()
    n_1=int(message[:256],16)
    e_1=int(message[256:512],16)
    c_1=int(message[512:],16)
file.close()
with open("Frame18") as file:
    message=file.read()
    n_2=int(message[:256],16)
    e_2=int(message[256:512],16)
    c_2=int(message[512:],16)
file.close()
p=gcd(n_1,n_2)
q_1=n_1//p
phi_1=(p-1)*(q_1-1)
d_1=gmpy2.invert(e_1,phi_1)
c_1=pow(c_1,d_1,n_1)
ciphertext_1=hex(c_1)
print(ciphertext_1)
print(hex_to_char(ciphertext_1[-16:]))

q_2=n_2//p
phi_2=(p-1)*(q_2-1)
d_2=gmpy2.invert(e_2,phi_2)
c_2=pow(c_2,d_2,n_2)
ciphertext_2=hex(c_2)
print(ciphertext_2)
print(hex_to_char(ciphertext_2[-16:]))