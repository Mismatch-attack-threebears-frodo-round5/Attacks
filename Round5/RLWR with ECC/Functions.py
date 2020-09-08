import math
from random import randrange
import sympy as sp
from sympy.abc import x
from operator import sub

# q, p, t, b, n, h, mu, f
params_NIST1 = [2**10, 2**7, 2**3, 2**1, 490, 162, 318]
params_NIST3 = [2**12, 2**8, 2**2, 2**1, 756, 242, 410]
params_NIST5 = [2**12, 2**8, 2**2, 2**1, 940, 414, 490]

def h_3(q, p, t, b):
    z = max(p, t * q / p)
    return p / (2 * t) + p / (2 * b) - q / (2 * z)

# decode function used within the key mismatch oracle
def Decode(input, p, b, h3):
    return int(math.floor((b/p)*(input+h3))) % b

# returns the parameters corresponding to the given version
# version corresponds to the NIST security level, i.e. 1,3 or 5
def getParameters(version):
    if version == 1:
        return params_NIST1[0], params_NIST1[1], params_NIST1[2], params_NIST1[3], params_NIST1[4], params_NIST1[5], params_NIST1[6]
    elif version == 3:
        return params_NIST3[0], params_NIST3[1], params_NIST3[2], params_NIST3[3], params_NIST3[4], params_NIST3[5], params_NIST3[6]
    elif version == 5:
        return params_NIST5[0], params_NIST5[1], params_NIST5[2], params_NIST5[3], params_NIST5[4], params_NIST5[5], params_NIST5[6]

# function which generates the secret key, i.e. a polynomial with coefficients from {-1,0,1}
def GenerateSecretPolynomial(version):
    q, p, t, b, n, h, mu = getParameters(version)
    coeff = []
    for i in range(n):
        coeff.append(0)
    for i in range(h):
        if i % 2 == 0:
            cond = True
            while cond:
                j = randrange(n)
                if coeff[j] == 0:
                    coeff[j] = 1
                    cond = False
        else:
            cond = True
            while cond:
                j = randrange(n)
                if coeff[j] == 0:
                    coeff[j] = -1
                    cond = False
    expr = sum(co * x ** i for i, co in enumerate(coeff))
    secret_key = sp.poly(expr)
    return secret_key

# function which returns first mu coefficients of the given polynomial
def Sample(pol, mu):
    result = []
    for i in range(mu):
        result.append(pol.nth(i))
    return result

# function which creates the reduction polynomial Phi
def GeneratePhi(version):
    q, p, t, b, n, h, mu = getParameters(version)
    coeff = []
    for i in range(n+1):
        coeff.append(1)
    expr = sum(co * x ** i for i, co in enumerate(coeff))
    pol = sp.poly(expr)
    return pol

# function which creates the reduction polynomial Xi
def GenerateXi(version):
    q, p, t, b, n, h, mu = getParameters(version)
    coeff = []
    coeff.append(-1)
    for i in range(1, n+1):
        coeff.append(0)
    coeff.append(1)
    expr = sum(co * x ** i for i, co in enumerate(coeff))
    pol = sp.poly(expr)
    return pol


# polynomial product reduced by f
def MultiplyPol(f,g,reduction):
    r = sp.rem(f.mul(g),reduction)
    return r


def NonZero(vec):
    count = 0
    for i in vec:
        if i != 0:
            count += 1
    return count

# the full key mismatch oracle
# quite slow because the polynomial multiplication is not very efficient
# guessed mesage is fixed to all zeroes
def FullOracle(version,v,U,S):
    xi = GenerateXi(version)
    q, p, t, b, n, h, mu = getParameters(version)
    h3 = h_3(q,p,t,b)
    if len(v) != mu:
        return False
    message = []
    for i in range(mu):
        message.append(0)
        v[i] = int(p/t)*v[i]
    x = Sample(MultiplyPol(S, U, xi), mu)
    x_diff = list(map(sub, v, x))
    x_mod = [x % p for x in x_diff]
    for i in range(mu):
        message[i] = Decode(x_mod[i], p, b, h3)
    # check if the message is corrected to all zeroes:
    if NonZero(message) <= 5:
        return '+'
    else:
        return '-'