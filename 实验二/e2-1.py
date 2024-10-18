from hashlib import sha1
from base64 import b64decode
from Crypto.Cipher import AES

#参数
C = '9MgYwmuPrjiecPMx61O6zIuy3MtIXQQ0E59T3xB6u0Gyf1gYs2i3K9Jxaa0zj4gTMazJuApwd6+jdyeI5iGHvhQyDHGVlAuYTgJrbFDrfB22Fpil2NfNnWFBTXyf7SDI'
K = '12345678<8<<<1110182<111116?<<<<<<<<<<<<<<<4'

#根据文献[2]求?
def solve_num(k):
    k = list(k)
    weights = [7, 3, 1, 7, 3, 1]
    sum = 0
    for i in range(21, 27):
        sum = (sum + int(k[i]) * weights[i - 21]) % 10
    k[27] = str(sum)
    return ''.join(k)

#求K_seed
def getK_seed(k):
    mrz_imt = k[:10] + k[13:20] + k[21:28]
    H_SHA1 = sha1(mrz_imt.encode()).hexdigest()
    return H_SHA1[:32]

#增加偶校验码以得到ka和kb
def getKab(k):
    kab = []
    a = bin(int(k,16))[2:]
    for i in range(0, len(a), 8):
        kab.append(a[i:i + 7])
        if a[i:i + 7].count('1') % 2 == 0:
            kab.append('1')
        else:
            kab.append('0')
    return hex(int(''.join(kab), 2))[2:]

#根据ka和kb求Key
def getKey(k):
    k = k + '00000001'
    H = sha1(bytes.fromhex(k)).hexdigest()
    return getKab(H[:16]) + getKab(H[16:32])

#求明文
def getP(C, k):
    C = b64decode(C)
    aes =  AES.new(bytes.fromhex(k), AES.MODE_CBC, bytes.fromhex('0'*32))
    return aes.decrypt(C).decode()

if __name__ == '__main__':
    K = solve_num(K)
    K_seed = getK_seed(K)
    Key = getKey(K_seed)
    P = getP(C, Key)
    print(P)