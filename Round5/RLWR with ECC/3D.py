from Functions import *
import BinaryTree1D as D1
import BinaryTree3D as D3
import json
from copy import copy
from random import randrange

# in fact, recover triplet of secret coefficients
def RecoverCoefficient(root, S, version, index):
    global queries
    q, p, t, b, n, h, mu = getParameters(version)
    index_1 = n - index + 3
    index_2 = n - index + 2
    index_3 = n - index + 1
    v = []
    guess = []
    for i in range(mu):
        v.append(0)
        guess.append(0)
    while root.left != None:
        U = sp.poly(root.alpha*x**index_1 + root.beta*x**index_2 + root.gamma*x**index_3, x)
        v[2] = root.value
        queries += 1
        t = FullOracle(version,v,U, S, guess)
        if  t == '-':
            root = root.left
        else:
            root = root.right
    return root.alpha, root.beta, root.gamma

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
    roots = {}
    for a in range(-1,2):
        for b in range(-1,2):
            for c in range(-1,2):
                key = str(a) + str(b) + str(c)
                path = 'data\RLWR_' + str(version) + '_3D_' + str(a) + '_' + str(b) + '_' + str(c) + '.txt'
                roots[key] = D3.reconstruct(D3.readjson(path))

    path = 'data\RLWR_' + str(version) + '_1D.txt'
    root_1D = D1.reconstruct(D1.readjson(path))

    q, p, t, b, n, h, mu = getParameters(version)
    recovered_secret = []
    recovered_secret.append(RecoverCoefficient1D(root_1D, S, version, 0))
    recovered_secret.append(RecoverCoefficient1D(root_1D, S, version, 1))
    recovered_secret.append(RecoverCoefficient1D(root_1D, S, version, 2))
    
    for i in range(3, n, 3):
        key = str(recovered_secret[i-3]) + str(recovered_secret[i-2]) + str(recovered_secret[i-1])
        a, b, c = RecoverCoefficient(roots[key], S, version, i)
        recovered_secret.append(a+recovered_secret[i-3])
        recovered_secret.append(b+recovered_secret[i-2])
        recovered_secret.append(c+recovered_secret[i-1])
    # n is not necessarily a multiple of 3:
    last = n - (n % 3)
    for i in range(last, n):
        recovered_secret.append((RecoverCoefficient1D(root_1D, S, version, i)))
    
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
print('RLWR, NIST level 1, dimension of the attack is 3')
print('Average number of queries to recover one secret coefficient: ' + str(queries/(total*(n - (n % 3) - 3))))
print('Success probability: ' + str(100*correct/total))
print('-----------------------------------------------------------------------------')
        
