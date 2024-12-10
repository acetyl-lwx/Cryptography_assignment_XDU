import gmpy2
#求最大公约数
def gcd(a, b):
    if b == 0:
        return a
    else:
        return gcd(b, a % b)

#求Mi
def Get_Mi(m_list, m):
    M_list = []
    for mi in m_list:
        M_list.append(m // mi)
    return M_list

#求Mi的逆元
def Get_resMi(M_list, m_list):
    resM_list = []
    for i in range(len(M_list)):
        resM_list.append((Get_ni(M_list[i], m_list[i])[0]+m_list[i])%m_list[i])
    return resM_list

#拓展欧几里得算法
def Get_ni(a, b):
    if b == 0:
        x = 1
        y = 0
        q = a
        return x, y, q
    ret = Get_ni(b, a % b)
    x = ret[0]
    y = ret[1]
    q = ret[2]
    temp = x
    x = y
    y = temp - a // b * y
    return x, y, q

#求解结果
def result(a_list, m_list):
    for i in range(len(m_list)):
        for j in range(i + 1, len(m_list)):
            if 1 != gcd(m_list[i], m_list[j]):
                print("不能直接使用中国剩余定理")
                return
    m = 1
    for mi in m_list:
        m *= mi
    Mi_list = Get_Mi(m_list, m)
    Mi_inverse = Get_resMi(Mi_list, m_list)
    x = 0
    xi_list = []
    for i in range(len(a_list)):
        xi = a_list[i] * Mi_list[i] * Mi_inverse[i]
        xi_list.append(xi)
        x += xi
        x %= m
    a,b=gmpy2.iroot(x,5)
    if b==1:
        x=a
    return x

def hex_to_char(hex_str):
    return bytes.fromhex(hex_str).decode('utf-8')

#读取数据
n=0
a_list=[]
m_list=[]
with open("frame3") as file:
    message = file.read()
    n=int(message[:256],16)
    e=int(message[256:512],16)
    c=int(message[512:],16)
    a_list.append(c)
    m_list.append(n)
file.close()
with open("frame8") as file:
    message = file.read()
    n=int(message[:256],16)
    e=int(message[256:512],16)
    c=int(message[512:],16)
    a_list.append(c)
    m_list.append(n)
file.close()
with open("frame12") as file:
    message = file.read()
    n=int(message[:256],16)
    e=int(message[256:512],16)
    c=int(message[512:],16)
    a_list.append(c)
    m_list.append(n)
file.close()
with open("frame16") as file:
    message = file.read()
    n=int(message[:256],16)
    e=int(message[256:512],16)
    c=int(message[512:],16)
    a_list.append(c)
    m_list.append(n)
file.close()
with open("frame20") as file:
    message = file.read()
    n=int(message[:256],16)
    e=int(message[256:512],16)
    c=int(message[512:],16)
    a_list.append(c)
    m_list.append(n)
file.close()
plaintext=hex(result(a_list, m_list))
print(hex_to_char(plaintext[-16:]))
