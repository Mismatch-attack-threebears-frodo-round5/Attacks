import math
import json
from BinaryTree1D import *
from copy import copy
from Functions import *

# function which recovers one secret coefficient 
def RecoverCoefficient(root, sk, version):
    global queries
    while root.left != None:
        alphas = [root.value, root.alpha]
        queries += 1
        t = Oracle(alphas, sk, version)
        if  t == '-':
            root = root.left
        else:
            root = root.right
    return root.alpha

# function which recovers the whole secret key
# makes use of the RecoverCoefficient function 
def RecoverSecretKey(root, sk, version):
    q, p, t, b, n, h, m = getParameters(version)
 
    recovered = []
    for i in range(n):
        recovered.append([])
        for j in range(m):
            recovered[i].append(0)

    # recover the secret key column by column
    for i in range(m):
        for j in range(n):
            recovered[j][i] = RecoverCoefficient(root, [sk[j][i]], version)
    return recovered

    
 

# NIST security level 1:
queries = 0
version = 1
correct = 0
total = 100
root = reconstruct(readjson('data\LWR_1_1D.txt'))
for i in range(total):
    sk = GenerateSecretKey(version)
    recovered = RecoverSecretKey(root, sk, version)
    if sk == recovered:
        correct += 1

print()
print()
print('LWR, NIST level 1, dimension of the attack is 1')
print('Average number of queries to recover the secret key: ' + str(queries/total))
print('Success probability: ' + str(100*correct/total))
print('-----------------------------------------------------------------------------')




# NIST security level 3:
queries = 0
version = 3
correct = 0
total = 100
root = reconstruct(readjson('data\LWR_3_1D.txt'))
for i in range(total):
    sk = GenerateSecretKey(version)
    recovered = RecoverSecretKey(root, sk, version)
    if sk == recovered:
        correct += 1

print()
print()
print('LWR, NIST level 3, dimension of the attack is 1')
print('Average number of queries to recover the secret key: ' + str(queries/total))
print('Success probability: ' + str(100*correct/total))
print('-----------------------------------------------------------------------------')


# NIST security level 5:
queries = 0
version = 5
correct = 0
total = 100
root = reconstruct(readjson('data\LWR_5_1D.txt'))
for i in range(total):
    sk = GenerateSecretKey(version)
    recovered = RecoverSecretKey(root, sk, version)
    if sk == recovered:
        correct += 1

print()
print()
print('LWR, NIST level 5, dimension of the attack is 1')
print('Average number of queries to recover the secret key: ' + str(queries/total))
print('Success probability: ' + str(100*correct/total))
print('-----------------------------------------------------------------------------')
