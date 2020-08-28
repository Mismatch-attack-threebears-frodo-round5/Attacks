import math
import json
from BinaryTree2D import *
from copy import copy
from Functions import *

# function which recovers a pair of secret coefficients
def RecoverCoefficient(root, sk, version):
    global queries
    while root.left != None:
        alphas = [root.value, root.alpha, root.beta]
        queries += 1

        t = Oracle(alphas, sk, version)
        if  t == '-':
            root = root.left
        else:
            root = root.right
    return [root.alpha, root.beta]

# function which recovers the whole secret key/almost the whole secret key
# depending on the length of the columns
# the possibly remaining row can be recovered by 1D version or some other method 
def RecoverSecretKey(root, sk, version):
    q, p, t, b, n, h, m = getParameters(version)

    recovered = []
    for i in range(2*int(n/2)):
        recovered.append([])
        for j in range(m):
            recovered[i].append(0)

    # recover the secret key column by column
    for i in range(m):
        for j in range(0, 2*int(n/2), 2):
            recovered[j][i], recovered[j+1][i] = RecoverCoefficient(root, [sk[j][i], sk[j+1][i]], version)
    return recovered



# NIST security level 1:
queries = 0
version = 1
correct = 0
total = 100
q, p, t, b, n, h, m = getParameters(version)
root = reconstruct(readjson('data\LWR_1_2D.txt'))
for i in range(total):
    sk = GenerateSecretKey(version)
    recovered = RecoverSecretKey(root, sk, version)
    if n % 2 == 0:
        if sk == recovered:
            correct += 1
    else:
        if sk[:-1] == recovered:
            correct += 1
print()
print()
print('LWR, NIST level 1, dimension of the attack is 2')
print('Average number of queries to recover one secret coefficient: ' + str(queries/(total*n*m)))
print('Success probability: ' + str(100*correct/total))
print('-----------------------------------------------------------------------------')


# NIST security level 3:
queries = 0
version = 3
correct = 0
total = 100
q, p, t, b, n, h, m = getParameters(version)
root = reconstruct(readjson('data\LWR_3_2D.txt'))
for i in range(total):
    sk = GenerateSecretKey(version)
    recovered = RecoverSecretKey(root, sk, version)
    if n % 2 == 0:
        if sk == recovered:
            correct += 1
    else:
        if sk[:-1] == recovered:
            correct += 1
print()
print()
print('LWR, NIST level 3, dimension of the attack is 2')
print('Average number of queries to recover one secret coefficient: ' + str(queries/(total*n*m)))
print('Success probability: ' + str(100*correct/total))
print('-----------------------------------------------------------------------------')



# NIST security level 5:
queries = 0
version = 5
correct = 0
total = 100
q, p, t, b, n, h, m = getParameters(version)
root = reconstruct(readjson('data\LWR_5_2D.txt'))
for i in range(total):
    sk = GenerateSecretKey(version)
    recovered = RecoverSecretKey(root, sk, version)
    if n % 2 == 0:
        if sk == recovered:
            correct += 1
    else:
        if sk[:-1] == recovered:
            correct += 1
print()
print()
print('LWR, NIST level 5, dimension of the attack is 2')
print('Average number of queries to recover one secret coefficient: ' + str(queries/(total*n*m)))
print('Success probability: ' + str(100*correct/total))
print('-----------------------------------------------------------------------------')


