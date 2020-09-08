from random import randrange
from math import ceil, floor
from Functions import cSHAKE256

class InvalidCiphertextException(Exception): pass
class InvalidParameterException(Exception): pass

def _hex(ba): return "".join("%02x" % c for c in ba)
def _bitarray(nbits): return bytearray(int(ceil(nbits / 8.)))

class Bear(object):
    CSHAKE_N = ""
    CSHAKE_S = "ThreeBears"
    _all = []

    def __str__(self):
        return self.NAME

    @staticmethod
    def _decodeInteger(vec):
        "Byte array -> single integer"
        return sum(v << (8 * i) for (i, v) in enumerate(vec))

    def _encodeVector(self, xs):
        "Array of integers mod N -> byte array"
        ret = bytearray()
        for x in xs:
            x %= self.N
            ret += bytearray([(x >> (8 * i)) & 0xFF for i in range(self.NBYTES_N)])
        return ret

    def _parameter_block(self):
        "Parameter block to domain-separate our hash from other ThreeBears"
        return bytearray([
            self.VERSION, self.PRIVATE_KEY_BYTES, self.MATRIX_SEED_BYTES, self.ENC_SEED_BYTES,
            self.IV_BYTES, self.SHARED_SECRET_BYTES, self.LGX, self.D & 0xFF, self.D >> 8,
            self.d, int(self.VARIANCE * 128) - 1, self.LPR_BITS, self.FEC_BITS, self.CCA
        ])

    def _hash(self, purpose, string, length):
        "Hash a byte string with diversified cSHAKE XOF"
        return cSHAKE256(N=self.CSHAKE_N, S=self.CSHAKE_S).hash(
            self._parameter_block() + bytearray([0, purpose]) + string, length=length)

    def _psi(self, byte):
        "Per-digit noise distribution"
        adj = int(self.VARIANCE * 128)
        ret = 0
        while adj > 64:
            ret += ((byte + 64) >> 8) + ((byte - 64) >> 8)
            byte = (byte << 2) & 0xFF
            adj -= 64
        ret += ((byte + adj) >> 8) + ((byte - adj) >> 8)
        return ret

    def _noise(self, why, seed, iv):
        "Sample from noise distribution"
        expanded = self._hash(why, seed + bytearray([iv]), length=self.D)
        return sum(self._psi(byte) << (self.LGX * i)
                   for i, byte in enumerate(expanded))


    # this function simulates the key mismatch oracle
    # it uses the functions from the ThreeBears's implementation
    def oracle(self, sk, capsule, guess):
        global queries
        queries += 1

        "Decrypt a capsule"
        nb = self.NBYTES_N
        d = self.d

        a_vector = sk
        B_vector = [self._decodeInteger(capsule[i * nb:(i + 1) * nb]) for i in range(d)]
        c = sum(a * bb for a, bb in zip(a_vector, B_vector)) * self.CLAR % self.N

        assert (self.LPR_BITS == 4)
        seed = _bitarray(self.ENCRYPTED_BITS)
        demlen = int(ceil(self.ENCRYPTED_BITS * self.LPR_BITS / 8.))
        for i, byte in enumerate(capsule[nb * d:nb * d + demlen]):
            lo_ours = c >> (self.LGX * (i + 1) - 5)
            hi_ours = c >> (self.LGX * (self.D - i) - 5)
            lo_delta = 2 * byte + 8 - lo_ours
            hi_delta = 2 * (byte >> 4) + 8 - hi_ours
            seed[i / 4] |= ((lo_delta >> 4 & 1) | (hi_delta >> 3 & 2)) << ((2 * i) % 8)

        if self.FEC_BITS:
            ones = 0
            for i in range(len(seed)):
                if seed[i] != 0:
                    ones += ManuallECC(seed[i])
            if ones < 3:
                return True
            else:
                return False
        else:
            if seed == guess:
                return True
            else:
                return False

    def __init__(self, name, variance, d, cca, useFec, IV_BYTES=0, D=312, lgx=10):
        "Create a ThreeBears instance with given parameters"
        # Parameter block
        self.VERSION = 1
        self.PRIVATE_KEY_BYTES = 40
        self.MATRIX_SEED_BYTES = 24
        self.ENC_SEED_BYTES = 32
        self.IV_BYTES = IV_BYTES
        self.TARGHI_UNRUH_BYTES = 0
        self.SHARED_SECRET_BYTES = 32
        self.LGX = lgx
        self.D = D
        self.d = d
        self.VARIANCE = variance
        self.LPR_BITS = 4
        self.FEC_BITS = 18 if useFec else 0
        self.CCA = cca

        # Derived parameters
        self.x = 2 ** lgx
        self.N = self.x ** D - self.x ** (D // 2) - 1
        self.NBYTES_N = int(ceil(lgx * D / 8.))
        self.CLAR = self.x ** (D // 2) - 1
        self.ENCRYPTED_BITS = self.ENC_SEED_BYTES * 8 + self.FEC_BITS

        self.NAME = name
        Bear._all.append(self)

#######=====================================================================================================######

# structure to keep the binary tree
# value is number between 0 and 15, it the paper this is called node.value
# value determines the query to the oracle
# coeff is the value of the coefficient, defined only for the leaves
class Node:
    def __init__(self, left, right, value, coeff):
        self.left=left
        self.right=right
        self.value = value
        self.coeff=coeff

# input is byte, output is number of bits which are zero
# we used this function because their error-correction does not work
# for our purposes it is enough to check if the message is corrected to all zeroes, which is possible to deduce
# from the number of non zero bits
def ManuallECC(number):
    result = 0
    while number != 0:
        result += (number % 2)
        number = number//2
    return result

# manual construction of the tree T1
# for the range [-2,2]
def TreeT1():
    node_00 = Node(None, None, None, 0)
    node_010 = Node(None, None, None, 1)
    node_011 = Node(None, None, None, 2)
    node_11 = Node(None, None, None, -1)
    node_10 = Node(None, None, None, -2)
    node_01 = Node(node_010, node_011, 5, None)
    node_0 = Node(node_00, node_01, 4, None)
    node_1 = Node(node_10, node_11, 2, None)
    root = Node(node_0, node_1, 11, None)
    return root

# manual construction of the tree T2
# for the range [-1,1]
def TreeT2():
    node_00 = Node(None, None, None, 0)
    node_01 = Node(None, None, None, 1)
    node_0 = Node(node_00, node_01, 4, None)
    node_1 = Node(None, None, None, -1)
    root = Node(node_0, node_1, 11, None)
    return root

# generate the secret key
# it uses the function from ThreeBears's implementation
def GenerateSecretKey(bear):
    global ask
    sk = [bear._noise(1, ask, i) for i in range(bear.d)]
    ask = bear._hash(randrange(0,256), ask, len(ask))
    return sk

# the main loop for recovering the secret coefficients
def Recover(bear, sk, Tree):
    recovered_sk = [0] * bear.d
    for i in range(0, bear.d):
        for j in range(0,312):
            recovered_sk[i] += (RecoverCoefficient(i, j, bear, sk, Tree) << (bear.LGX * j))
    return recovered_sk

# function which recovers the secret coefficient s_{i,j} using the Tree
def RecoverCoefficient(i, j, bear, sk, Tree):
    guess = bytearray(32)
    iv = bytearray(bear.IV_BYTES)
    C1 = [0]*bear.d
    if bear.FEC_BITS: # dem is actually encr, but in bytes, not nibbles
        dem = bytearray(137)
        dem[128] = 136
    else:
        dem = bytearray(128)
    if j >= 0 and j <= 127:
        C1[i] = 55 * (bear.x) ** 156
        k = j
        factor = 1
    elif j >= 184 and j <= 311:
        C1[i] = 55 * (bear.x) ** 156
        k = 311 - j
        factor = 16
    elif j >= 128 and j <= 155:
        C1[i] =  55
        k = 311 - (j + 156)
        factor = 16
    elif j >= 156 and j <= 183:
        C1[i] = 55 * (bear.x) ** 212
        k = 311 - (j + 56)
        factor = 16
    bpk = bear._encodeVector(C1)
    node = Tree
    while node.value != None:
        dem[k] = factor*node.value
        capsule = bpk + dem + iv
        output = bear.oracle(sk, capsule, guess)
        if output == True:
            node = node.right
        else:
            node = node.left
    return node.coeff



# This targets also the three alternative parameter sets which do not use the error-correcting code
""" 
queries = 0
success = 0
limit = 10
print 'Number of iterations of the attack: ' + str(limit)
print
variance = [1.0, 7.0/8, 3.0/4, 5.0/8, 1.0/2, 7.0/16]
dimension = [2,3,4,2,3,4]
fecCode = [True, True, True, False, False, False]
for var, dim, fec in zip(variance, dimension, fecCode):
    bear = Bear("Experiment", var, dim, False, fec)
    pada = bytearray(bear.PRIVATE_KEY_BYTES - bear.SHARED_SECRET_BYTES)
    ask = bytearray(bear.SHARED_SECRET_BYTES) + pada

    queries = 0
    success = 0
    print '--------------------------'
    print 'Variance: ' + str(var) + ', Dimension of the module: ' + str(dim) + ', Error-correction: ' + str(fec)

    if var == 1.0/2 or var == 7.0/16:
        tree = TreeT2()
    else:
        tree = TreeT1()

    for k in range(0,limit):
        sk = GenerateSecretKey(bear)
        recovered_sk = Recover(bear, sk, tree)
        if sk == recovered_sk:
            success += 1
    print 'Average number of queries: ' + str(queries/(limit + 0.0))
    print 'Success probability: ' + str(success/(limit + 0.0))
    print
    print
"""



# limit = the number of iterations of the attack
queries = 0
success = 0
limit = 10
print
print 'Number of iterations of the attack: ' + str(limit)
print '----------------------------------------'
print
print
variance = [1.0, 7.0/8, 3.0/4]
dimension = [2,3,4]
names = ['BabyBear:', 'MamaBear:', 'PapaBear:']
for var, dim, name in zip(variance, dimension, names):
    bear = Bear("Experiment", var, dim, False, True)
    pada = bytearray(bear.PRIVATE_KEY_BYTES - bear.SHARED_SECRET_BYTES)
    ask = bytearray(bear.SHARED_SECRET_BYTES) + pada

    queries = 0
    success = 0

    print name

    tree = TreeT1()

    for k in range(0,limit):
        sk = GenerateSecretKey(bear)
        recovered_sk = Recover(bear, sk, tree)
        if sk == recovered_sk:
            success += 1
    print 'Average number of queries to recover the whole secret key: ' + str(queries/(limit + 0.0))
    print 'Average success probability: ' + str(success/(limit + 0.0))
    print
    print




