import math
import json
from BinaryTree4D import *
from copy import copy
import time
from Functions import *

def RecoverCoefficient(root, sk, version):
    global queries
    while root.left != None:
        alphas = [root.value, root.alpha, root.beta, root.gamma, root.delta]
        queries += 1
        t = Oracle(alphas, sk, version)
        if  t == '-':
            root = root.left
        else:
            root = root.right
    return [root.alpha, root.beta, root.gamma, root.delta]

def RecoverSecretKey(root, sk, version):
    # get the parameter set
    q, p, t, b, n, h, m = getParameters(version)
    # prepare the structure for the recovered secret key
    recovered = []
    for i in range(4*int(n/4)):
        recovered.append([])
        for j in range(m):
            recovered[i].append(0)

    # recover the secret key column by column
    for i in range(m):
        for j in range(0, 4*int(n/4), 4):
            recovered[j][i], recovered[j+1][i], recovered[j+2][i], recovered[j+3][i] = RecoverCoefficient(root, [sk[j][i], sk[j+1][i], sk[j+2][i], sk[j+3][i]], version)
    return recovered



# NIST security level 1:
queries = 0
version = 1
correct = 0
total = 100
q, p, t, b, n, h, m = getParameters(version)
root = reconstruct(readjson('data\LWR_1_4D.txt'))
for i in range(total):
    sk = GenerateSecretKey(version)
    recovered = RecoverSecretKey(root, sk, version)
    if n % 4 == 0:
        if sk == recovered:
            correct += 1
    elif n % 4 == 1:
        if sk[:-1] == recovered:
            correct += 1
    elif n % 4 == 2:
        if sk[:-2] == recovered:
            correct += 1
    else:
        if sk[:-3] == recovered:
            correct += 1

print('LWR, dimension 4, NIST security level 1')
print('Average number of queries to recover one secret coefficient: ' + str(queries/(total*n*m)))
print('Success probability: ' + str(100*correct/total))
print('-----------------------------------------------')
print()




# NIST security level 3:
queries = 0
version = 3
correct = 0
total = 100
q, p, t, b, n, h, m = getParameters(version)
root = reconstruct(readjson('data\LWR_3_4D.txt'))
for i in range(total):
    sk = GenerateSecretKey(version)
    recovered = RecoverSecretKey(root, sk, version)
    if n % 4 == 0:
        if sk == recovered:
            correct += 1
    elif n % 4 == 1:
        if sk[:-1] == recovered:
            correct += 1
    elif n % 4 == 2:
        if sk[:-2] == recovered:
            correct += 1
    else:
        if sk[:-3] == recovered:
            correct += 1

print('LWR, dimension 4, NIST security level 3')
print('Average number of queries to recover one secret coefficient: ' + str(queries/(total*n*m)))
print('Success probability: ' + str(100*correct/total))
print('-----------------------------------------------')
print()
