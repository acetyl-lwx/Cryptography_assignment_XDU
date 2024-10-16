import hashlib
import itertools
import time

SHA1_HASH_TARGET = "67ae1a64661ac8b4494666f58c4822408dd0a3e4"
CHAR_SETS = [['Q', 'q'], ['W', 'w'], ['5', '%'], ['8', '('], ['=', '0'], ['I', 'i'], ['*', '+'], ['n', 'N']]

def sha1_encrypt(input_string):
    sha = hashlib.sha1(input_string.encode())
    hashed_value = sha.hexdigest()
    return hashed_value

# 暴力破解
start_time = time.time()
initial_string = "0" * 8
current_password = list(initial_string)
for i in range(2):
    current_password[0] = CHAR_SETS[0][i]
    for j in range(2):
        current_password[1] = CHAR_SETS[1][j]
        for k in range(2):
            current_password[2] = CHAR_SETS[2][k]
            for l in range(2):
                current_password[3] = CHAR_SETS[3][l]
                for m in range(2):
                    current_password[4] = CHAR_SETS[4][m]
                    for n in range(2):
                        current_password[5] = CHAR_SETS[5][n]
                        for o in range(2):
                            current_password[6] = CHAR_SETS[6][o]
                            for p in range(2):
                                current_password[7] = CHAR_SETS[7][p]
                                permutation = "".join(current_password)
                                for perm in itertools.permutations(permutation, 8):
                                    candidate_password = "".join(perm)
                                    hashed_candidate = sha1_encrypt(candidate_password)
                                    if hashed_candidate == SHA1_HASH_TARGET:
                                        print("password:", candidate_password)
                                        end_time = time.time()
                                        print(f"time:{end_time - start_time}s")
                                        exit(0)
