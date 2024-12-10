import gmpy2

def factor(n):
    a=gmpy2.iroot(n,2)[0]
    while True:
        a+=1
        b2=a*a-n
        if gmpy2.is_square(b2):
            b2=gmpy2.mpz(b2)
        b,xflag=gmpy2.iroot(b2,2)
        assert xflag
        return (a-b,a+b)
    
def hex_to_char(hex_str):
    return bytes.fromhex(hex_str).decode('utf-8')

with open("Frame10") as file:
    message = file.read()
    n=int(message[:256],16)
    e=int(message[256:512],16)
    c=int(message[512:],16)
file.close()
p,q=factor(n)
print("p=",hex(p))
print("q=",hex(q))
fai=(p-1)*(q-1)
d=gmpy2.invert(e,fai)
print("d=",hex(d))
m=gmpy2.powmod(c,d,n)
print("m=",hex(m))
plaintext=hex(m)[-16:]
print(hex_to_char(plaintext))
