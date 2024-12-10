import gmpy2
def pollard(N):
    a = 2
    B = 2
    while True:
        a = gmpy2.powmod(a, B, N)
        res = gmpy2.gcd(a-1, N)
        if res != 1 and res != N:
            q = N // res
            return res, q
        B += 1

def hex_to_char(hex_str):
    return bytes.fromhex(hex_str).decode('utf-8')

with open("Frame19") as file:
    message = file.read()
    n=int(message[:256],16)
    e=int(message[256:512],16)
    c=int(message[512:],16)
file.close()
p,q=pollard(n)
print("p=",hex(p))
print("q=",hex(q))
fai=(p-1)*(q-1)
d=gmpy2.invert(e,fai)
print("d=",hex(d))
m=gmpy2.powmod(c,d,n)
print("m=",hex(m))
plaintext=hex(m)[-16:]
print(hex_to_char(plaintext))