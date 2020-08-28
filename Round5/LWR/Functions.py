import math
from random import randrange

# q, p, t, b, n, h, overbar_m
params_NIST1 = [2**13, 2**10, 2**7, 2**3, 594, 230, 7]
params_NIST3 = [2**13, 2**10, 2**7, 2**3, 881, 238, 8]
params_NIST5 = [2**15, 2**12, 2**7, 2**4, 1186, 712, 8]

def h_3(q, p, t, b):
    z = max(p, t * q / p)
    return p / (2 * t) + p / (2 * b) - q / (2 * z)

# returns the parameters corresponding to the given version
# version corresponds to the NIST security level, i.e. 1,3 or 5
def getParameters(version):
    if version == 1:
        return params_NIST1[0], params_NIST1[1], params_NIST1[2], params_NIST1[3], params_NIST1[4], params_NIST1[5], params_NIST1[6]
    elif version == 3:
        return params_NIST3[0], params_NIST3[1], params_NIST3[2], params_NIST3[3], params_NIST3[4], params_NIST3[5], params_NIST3[6]
    elif version == 5:
        return params_NIST5[0], params_NIST5[1], params_NIST5[2], params_NIST5[3], params_NIST5[4], params_NIST5[5], params_NIST5[6]

# this function simulates the key mismatch oracle
# this function takes into account that all positions except one decode to zero bits: so this function 
# does not have to compute the full matrix product, but only one entry in this product which can possibly 
# decode to non-zero bits
def Oracle(alphas, targets, version):
    q, p, t, b, n, h, m = getParameters(version)
    h3 = h_3(q, p, t, b)
    v = int(p/t) * alphas[0]
    for i in range(len(targets)):
        v -= alphas[i+1] * targets[i]
    v = v % p
    dec = Decode(v, p, b, h3)
    if dec == 0:
        return '+'
    else:
        return '-'

# decode function used within the key mismatch oracle
def Decode(input, p, b, h3):
    return int(math.floor((b/p)*(input+h3))) % b

# function which generates the secret key, i.e. a matrix with entries from {-1,0,1} 
def GenerateSecretKey(version):
    q, p, t, b, n, h, m = getParameters(version)
    matrix = []

    for i in range(n):
        matrix.append([])
        for j in range(m):
            matrix[i].append(0)
    for j in range(m):
        for i in range(h):
            cond = True
            if i % 2 == 0:
                while cond:
                    k = randrange(n)
                    if matrix[k][j] == 0:
                        matrix[k][j] = 1
                        cond = False
            else:
                while cond:
                    k = randrange(n)
                    if matrix[k][j] == 0:
                        matrix[k][j] = -1
                        cond = False
    return matrix

