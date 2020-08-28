import math
from random import randrange
import sys
import random
from BinaryTree1D import *

prob_640 = [1, 4, 17, 56, 164, 422, 958, 1918, 3384, 5264, 7216, 8720, 9288, 8720, 7216, 5264, 3384, 1918, 958, 422, 164, 56, 17, 4, 1]
prob_976 = [1, 6, 29, 118, 396, 1101, 2545, 4882, 7774, 10277, 11278, 10277, 7774, 4882, 2545, 1101, 396, 118, 29, 6, 1]
prob_1344 = [2, 40, 364, 2023, 6876, 14320, 18286, 14320, 6876, 2023, 364, 40, 2]
table_640 = [1, 5, 22, 78, 242, 664, 1622, 3540, 6924, 12188, 19404, 28124, 37412, 46132, 53348, 58612, 61996, 63914, 64872, 65294, 65458, 65514, 65531, 65535]
table_976 = [1, 7, 36, 154, 550, 1651, 4196, 9078, 16852, 27129, 38407, 48684, 56458, 61340, 63885, 64986, 65382, 65500, 65529, 65535]
table_1344 = [2, 42, 406, 2429, 9305, 23625, 41911, 56231, 63107, 65130, 65494, 65534]
max = 65536

def Sample(version):
    if version == 640:
        limit = 12
        table = table_640.copy()
    elif version == 976:
        limit = 10
        table = table_976.copy()
    elif version == 1344:
        limit = 6
        table = table_1344.copy()
    a = randrange(max)
    res = -limit
    for i in range(2*limit):
        if a >= table[i]:
            res += 1
        else:
            return res
    return res

def Decode(input, q, B):
    return int(math.floor(input * (2**B/q) + 1/2)) % 2**B

def Oracle(alphas, targets, q, B):
    global queries
    queries += 1
    C2 = alphas[0]
    for i in range(len(targets)):
        C2 -= alphas[i+1] * targets[i]
    C2 = C2 % q
    dec = Decode(C2, q, B)
    if dec == 0:
        return '+'
    else:
        return '-'


def RecoverCoefficient(root, sk, i, j, version):
    if version == 640:
        q = 32768
        B = 2
    elif version == 976:
        q = 65536
        B = 3
    elif version == 1344:
        q = 65536
        B = 4
    while root.left != None:
        alphas = [root.value, 1]
        targets = [sk[i][j]]
        t = Oracle(alphas, targets, q, B)
        if  t == '-':
            root = root.left
        else:
            root = root.right
    return root.value


root = reconstruct(readjson("data\Frodo640_1D.txt"))
total = 100
correct = 0
queries = 0
version = 640
for k in range(total):
    sk = 640*[8*[0]]
    for i in range(640):
        for j in range(8):
            sk[i][j] = Sample(version)
    recover = 640*[8*[0]]
    for i in range(640):
        for j in range(8):
            recover[i][j] = RecoverCoefficient(root, sk, i, j, 640)
    if recover == sk:
        correct += 1
print('-----------------------------------------------------------------------')
print('Targeting Frodo640, dimension of the attack is 1:')
print()
print('Average success probability: ' + str(correct/total))
print('Average number of queries to recover 1 secret coefficients: ' + str(queries/(640*8*total)))
print('Average number of queries to recover the whole secret key: ' + str(queries/total))
print('-----------------------------------------------------------------------')
print()
print()

root = reconstruct(readjson("data\Frodo976_1D.txt"))
total = 100
correct = 0
queries = 0
version = 976
for k in range(total):
    sk = version*[8*[0]]
    for i in range(version):
        for j in range(8):
            sk[i][j] = Sample(version)
    recover = version*[8*[0]]
    for i in range(version):
        for j in range(8):
            recover[i][j] = RecoverCoefficient(root, sk, i, j, version)
    if recover == sk:
        correct += 1
print('-----------------------------------------------------------------------')
print('Targeting Frodo976, dimension of the attack is 1:')
print()
print('Average success probability: ' + str(correct/total))
print('Average number of queries to recover 1 secret coefficients: ' + str(queries/(976*8*total)))
print('Average number of queries to recover the whole secret key: ' + str(queries/total))
print('-----------------------------------------------------------------------')
print()
print()

root = reconstruct(readjson("data\Frodo1344_1D.txt"))
total = 100
correct = 0
queries = 0
version = 1344
for k in range(total):
    sk = version*[8*[0]]
    for i in range(version):
        for j in range(8):
            sk[i][j] = Sample(version)
    recover = version*[8*[0]]
    for i in range(version):
        for j in range(8):
            recover[i][j] = RecoverCoefficient(root, sk, i, j, version)
    if recover == sk:
        correct += 1
print('-----------------------------------------------------------------------')
print('Targeting Frodo1344, dimension of the attack is 1:')
print()
print('Average success probability: ' + str(correct/total))
print('Average number of queries to recover 1 secret coefficients: ' + str(queries/(1344*8*total)))
print('Average number of queries to recover the whole secret key: ' + str(queries/total))
print('-----------------------------------------------------------------------')
print()
print()