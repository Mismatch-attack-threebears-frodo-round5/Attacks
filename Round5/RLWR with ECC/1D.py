from Functions import *
from BinaryTree1D import *
from copy import copy
from random import randrange

# function that recovers the coefficients with appropriately small degree
def RecoverCoefficientStart(root, S, version, index):
    global queries
    guess = []
    v = []
    q, p, t, b, n, h, mu = getParameters(version)
    for i in range(mu):
        guess.append(0)
        v.append(0)
    while root.left != None:
        U = sp.poly(root.alpha, x)
        v[index] = root.value
        queries += 1
        t = FullOracle(version,v,U, S, guess)
        if  t == '-':
            root = root.left
        else:
            root = root.right
    return root.alpha

# function that recovers the remaining secret coefficients 
def RecoverCoefficientRest(root, S, version, index, temp):
    global queries
    q, p, t, b, n, h, mu = getParameters(version)
    modulus = int(p/t)
    index = n - index + mu
    v = []
    guess = []
    for i in range(mu):
        v.append(0)
        guess.append(0)
    while root.left != None:
        U = sp.poly(root.alpha*x**index, x)
        v[mu-1] = root.value - int(root.alpha*temp/modulus)
        queries += 1
        t = FullOracle(version,v,U, S, guess)
        if  t == '-':
            root = root.left
        else:
            root = root.right
    return root.alpha

# function that recovers the whole secret key
def Recover(root, S, version):
    q, p, t, b, n, h, mu = getParameters(version)
    recovered_secret = []
    for i in range(mu):
        a = RecoverCoefficientStart(root, S, version, i)
        recovered_secret.append(a)
    for i in range(mu, n):
        a = RecoverCoefficientRest(root, S, version, i, recovered_secret[i-mu])
        recovered_secret.append(a)
    return recovered_secret

# this implementation is quite small because of the non-optimized polynomial multiplication
# when targeting the scheme in real, faster multiplication will be used
# this code is only to show that the attack works is described  

#NIST security level 1:
queries = 0
version = 1
total = 1
correct = 0
q, p, t, b, n, h, mu = getParameters(version)
root = reconstruct(readjson('data\RLWR_1_1D.txt'))
for i in range(total):
    S = GenerateSecretPolynomial(version=version)
    recovered = Recover(root, S, version=version)
    check = 0
    for j in range(len(recovered)):
        if recovered[j] != S.nth(j):
            check = 1
    if check == 0:
        correct += 1
print()
print()
print('RLWR, NIST level 1, dimension of the attack is 1')
print('Average number of queries to recover one secret coefficient: ' + str(queries/(total*n)))
print('Success probability: ' + str(100*correct/total))
print('-----------------------------------------------------------------------------')
        
#NIST security level 3:
queries = 0
version = 3
total = 1
correct = 0
q, p, t, b, n, h, mu = getParameters(version)
root = reconstruct(readjson('data\RLWR_3_1D.txt'))
for i in range(total):
    S = GenerateSecretPolynomial(version=version)
    recovered = Recover(root, S, version=version)
    check = 0
    for j in range(len(recovered)):
        if recovered[j] != S.nth(j):
            check = 1
    if check == 0:
        correct += 1
print()
print()
print('RLWR, NIST level 3, dimension of the attack is 1')
print('Average number of queries to recover one secret coefficient: ' + str(queries/(total*n)))
print('Success probability: ' + str(100*correct/total))
print('-----------------------------------------------------------------------------')

#NIST security level 5:
queries = 0
version = 5
total = 1
correct = 0
q, p, t, b, n, h, mu = getParameters(version)
root = reconstruct(readjson('data\RLWR_5_1D.txt'))
for i in range(total):
    S = GenerateSecretPolynomial(version=version)
    recovered = Recover(root, S, version=version)
    check = 0
    for j in range(len(recovered)):
        if recovered[j] != S.nth(j):
            check = 1
    if check == 0:
        correct += 1
print()
print()
print('RLWR, NIST level 5, dimension of the attack is 1')
print('Average number of queries to recover one secret coefficient: ' + str(queries/(total*n)))
print('Success probability: ' + str(100*correct/total))
print('-----------------------------------------------------------------------------')


