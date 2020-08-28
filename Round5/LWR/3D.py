import math
import json
from BinaryTree3D import *
from copy import copy
from Functions import *

# function which recovers a triplet of secret coefficients
def RecoverCoefficient(root, sk, version):
    global queries
    while root.left != None:
        alphas = [root.value, root.alpha, root.beta, root.gamma]
        queries += 1
        t = Oracle(alphas, sk, version)
        if  t == '-':
            root = root.left
        else:
            root = root.right
    return [root.alpha, root.beta, root.gamma]

# function which recovers the whole secret key/almost the whole secret key
# depending on the length of the columns
# the possibly remaining row/2 rows can be recovered by 1D version, 2D version or some other method  
def RecoverSecretKey(root, sk, version):
    # get the parameter set
    q, p, t, b, n, h, m = getParameters(version)
    
    recovered = []
    for i in range(3*int(n/3)):
        recovered.append([])
        for j in range(m):
            recovered[i].append(0)

    # recover the secret key column by column
    for i in range(m):
        for j in range(0, 3*int(n/3), 3):
            recovered[j][i], recovered[j+1][i], recovered[j+2][i] = RecoverCoefficient(root, [sk[j][i], sk[j+1][i], sk[j+2][i]], version)
    return recovered


# NIST security level 1:
queries = 0
version = 1
correct = 0
total = 100
q, p, t, b, n, h, m = getParameters(version)
root = reconstruct(readjson('data\LWR_1_3D.txt'))
for i in range(total):
    sk = GenerateSecretKey(version)
    recovered = RecoverSecretKey(root, sk, version)
    if n % 3 == 0:
        if sk == recovered:
            correct += 1
    elif n % 3 == 1:
        if sk[:-1] == recovered:
            correct += 1
    else:
        if sk[:-2] == recovered:
            correct += 1

print()
print()
print('LWR, NIST level 1, dimension of the attack is 3')
print('Average number of queries to recover one secret coefficient: ' + str(queries/(total*n*m)))
print('Success probability: ' + str(100*correct/total))
print('-----------------------------------------------------------------------------')



# NIST security level 3:
queries = 0
version = 3
correct = 0
total = 100
q, p, t, b, n, h, m = getParameters(version)
root = reconstruct(readjson('data\LWR_3_3D.txt'))
for i in range(total):
    sk = GenerateSecretKey(version)
    recovered = RecoverSecretKey(root, sk, version)
    if n % 3 == 0:
        if sk == recovered:
            correct += 1
    elif n % 3 == 1:
        if sk[:-1] == recovered:
            correct += 1
    else:
        if sk[:-2] == recovered:
            correct += 1

print()
print()
print('LWR, NIST level 3, dimension of the attack is 3')
print('Average number of queries to recover one secret coefficient: ' + str(queries/(total*n*m)))
print('Success probability: ' + str(100*correct/total))
print('-----------------------------------------------------------------------------')



# NIST security level 5:
queries = 0
version = 5
correct = 0
total = 100
q, p, t, b, n, h, m = getParameters(version)
root = reconstruct(readjson('data\LWR_5_3D.txt'))
for i in range(total):
    sk = GenerateSecretKey(version)
    recovered = RecoverSecretKey(root, sk, version)
    if n % 3 == 0:
        if sk == recovered:
            correct += 1
    elif n % 3 == 1:
        if sk[:-1] == recovered:
            correct += 1
    else:
        if sk[:-2] == recovered:
            correct += 1

print()
print()
print('LWR, NIST level 5, dimension of the attack is 3')
print('Average number of queries to recover one secret coefficient: ' + str(queries/(total*n*m)))
print('Success probability: ' + str(100*correct/total))
print('-----------------------------------------------------------------------------')

