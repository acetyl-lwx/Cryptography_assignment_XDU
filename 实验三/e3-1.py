#求大公因数
def gcd(a, b):
    if b == 0:
        return a
    else:
        return gcd(b, a % b)

#枚举e
p, q, sum, e = 1009, 3643, 0, 3
phi = (p-1) * (q-1)
while (e < phi):
    if gcd(e, phi)==1 and gcd(e-1, q-1)==2 and gcd(e-1, p-1)==2:
        sum += e
    e += 2
    
print("The sum of e is", sum)