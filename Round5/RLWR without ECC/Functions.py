import math
from random import randrange
import sympy as sp
from sympy.abc import x
from operator import sub

# q, p, t, b, n, h, mu
params_NIST1 = [2**11, 2**8, 2**4, 2**1, 618, 104, 128]
params_NIST3 = [2**13, 2**9, 2**4, 2**1, 786, 384, 192]
params_NIST5 = [2**14, 2**9, 2**4, 2**1, 1018, 428, 256]

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

# function which creates the reduction polynomial
def GeneratePhi(version):
    q, p, t, b, n, h, mu = getParameters(version)
    coeff = []
    for i in range(n+1):
        coeff.append(1)
    expr = sum(co * x ** i for i, co in enumerate(coeff))
    pol = sp.poly(expr)
    return pol

# polynomial product reduced by phi
def MultiplyPol(f,g,phi):
    r = sp.rem(f.mul(g),phi)
    return r

# the full key mismatch oracle
# quite small because the polynomial multiplication is not very efficient    
def FullOracle(version,v,U,S, guess):
    phi = GeneratePhi(version)
    q, p, t, b, n, h, mu = getParameters(version)
    h3 = h_3(q,p,t,b)
    if len(v) != mu:
        return False
    message = []
    for i in range(mu):
        message.append(0)
        v[i] = int(p/t)*v[i]
    x = Sample(MultiplyPol(S, U, phi), mu)
    x_diff = list(map(sub, v, x))
    x_mod = [x % p for x in x_diff]
    for i in range(mu):
        message[i] = Decode(x_mod[i], p, b, h3)

    if message == guess:
        return '+'
    else:
        return '-'
