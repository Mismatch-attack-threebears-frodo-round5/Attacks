from Functions import *
import BinaryTree2D as D2
import BinaryTree1D as D1
import numpy as np
import json
from copy import copy
from random import randrange

# function that recovers a pair of secret coefficients 
def RecoverCoefficient(root, S, version, index):
    global queries
    q, p, t, b, n, h, mu = getParameters(version)
    index_1 = n - index + 2
    index_2 = n - index + 1
    v = []
    guess = []
    for i in range(mu):
        v.append(0)
        guess.append(0)
    while root.left != None:
        U = sp.poly(root.alpha*x**index_1 + root.beta*x**index_2, x)
        v[1] = root.value
        queries += 1
        t = FullOracle(version,v,U, S, guess)
        if  t == '-':
            root = root.left
        else:
            root = root.right
    return root.alpha, root.beta

# function that recovers a secret coefficient, used to recover the first 
# two secret coefficients 
def RecoverCoefficient1D(root, S, version, index):
    guess = []
    v = []
    q, p, t, b, n, h, mu = getParameters(version)
    for i in range(mu):
        guess.append(0)
        v.append(0)
    while root.left != None:
        U = sp.poly(root.alpha, x)
        v[index] = root.value
        t = FullOracle(version,v,U, S, guess)
        if  t == '-':
            root = root.left
        else:
            root = root.right
    return root.alpha

# function that recovers the whole secret key
def Recover(S, version):
    global total
    path = 'data\RLWR_' + str(version) + '_2D_' + str(0) + '_' + str(0) + '.txt'
    root_00 = D2.reconstruct(D2.readjson(path))

    path = 'data\RLWR_' + str(version) + '_2D_' + str(1) + '_' + str(1) + '.txt'
    root_11 = D2.reconstruct(D2.readjson(path))

    path = 'data\RLWR_' + str(version) + '_2D_' + str(-1) + '_' + str(-1) + '.txt'
    root_mm = D2.reconstruct(D2.readjson(path))

    path = 'data\RLWR_' + str(version) + '_2D_' + str(1) + '_' + str(-1) + '.txt'
    root_1m = D2.reconstruct(D2.readjson(path))

    path = 'data\RLWR_' + str(version) + '_2D_' + str(0) + '_' + str(1) + '.txt'
    root_01 = D2.reconstruct(D2.readjson(path))

    path = 'data\RLWR_' + str(version) + '_2D_' + str(0) + '_' + str(-1) + '.txt'
    root_0m = D2.reconstruct(D2.readjson(path))


    path = 'data\RLWR_' + str(version) + '_2D_' + str(-1) + '_' + str(1) + '.txt'
    root_m1 = D2.reconstruct(D2.readjson(path))

    path = 'data\RLWR_' + str(version) + '_2D_' + str(1) + '_' + str(0) + '.txt'
    root_10 = D2.reconstruct(D2.readjson(path))

    path = 'data\RLWR_' + str(version) + '_2D_' + str(-1) + '_' + str(0) + '.txt'
    root_m0 = D2.reconstruct(D2.readjson(path))


    path = 'data\RLWR_' + str(version) + '_1D.txt'
    root_1D = D1.reconstruct(D1.readjson(path))

    roots = {'00': root_00, '11': root_11, '-1-1': root_mm, '1-1': root_1m, '01': root_01, '0-1': root_0m, '-11': root_m1, '10': root_10, '-10': root_m0}

    q, p, t, b, n, h, mu = getParameters(version)
    recovered_secret = []
    recovered_secret.append(RecoverCoefficient1D(root_1D, S, version, 0))
    recovered_secret.append(RecoverCoefficient1D(root_1D, S, version, 1))
    for i in range(2, n, 2):
        key = str(recovered_secret[i-2]) + str(recovered_secret[i-1])
        a, b = RecoverCoefficient(roots[key], S, version, i)
        recovered_secret.append(a+recovered_secret[i-2])
        recovered_secret.append(b+recovered_secret[i-1])
       
    return recovered_secret


    
# this implementation is quite slow because of the non-optimized polynomial multiplication
# when targeting the scheme in real, faster multiplication will be used
# this code is only to show that the attack works as described  

#NIST security level 1:
queries = 0
version = 1
total = 1
correct = 0
q, p, t, b, n, h, mu = getParameters(version)
for i in range(total):
    S = GenerateSecretPolynomial(version=version)
    recovered = Recover(S, version=version)
    check = 0
    for j in range(len(recovered)):
        if recovered[j] != S.nth(j):
            check = 1
    if check == 0:
        correct += 1
print()
print()
print('RLWR, NIST level 1, dimension of the attack is 2')
print('Average number of queries to recover one secret coefficient: ' + str(queries/(total*(n-2))))
print('Success probability: ' + str(100*correct/total))
print('-----------------------------------------------------------------------------')
        
#NIST security level 3:
queries = 0
version = 3
total = 1
correct = 0
q, p, t, b, n, h, mu = getParameters(version)
for i in range(total):
    S = GenerateSecretPolynomial(version=version)
    recovered = Recover(S, version=version)
    check = 0
    for j in range(len(recovered)):
        if recovered[j] != S.nth(j):
            check = 1
    if check == 0:
        correct += 1
print()
print()
print('RLWR, NIST level 3, dimension of the attack is 2')
print('Average number of queries to recover one secret coefficient: ' + str(queries/(total*(n-2))))
print('Success probability: ' + str(100*correct/total))
print('-----------------------------------------------------------------------------')

#NIST security level 5:
queries = 0
version = 5
total = 1
correct = 0
q, p, t, b, n, h, mu = getParameters(version)
for i in range(total):
    S = GenerateSecretPolynomial(version=version)
    recovered = Recover(S, version=version)
    check = 0
    for j in range(len(recovered)):
        if recovered[j] != S.nth(j):
            check = 1
    if check == 0:
        correct += 1
print()
print()
print('RLWR, NIST level 5, dimension of the attack is 2')
print('Average number of queries to recover one secret coefficient: ' + str(queries/(total*(n-2))))
print('Success probability: ' + str(100*correct/total))
print('-----------------------------------------------------------------------------')





