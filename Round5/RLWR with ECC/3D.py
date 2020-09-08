from Functions import *
from BinaryTree3D import *


# function that recovers the coefficients
def RecoverCoefficient(root, S, version, index):
    global queries
    v = []
    q, p, t, b, n, h, mu = getParameters(version)
    for i in range(mu):
        v.append(0)
    while root.left != None:
        U = sp.poly(root.alpha * x ** (n+1-index) + root.beta * x ** (n-index) + root.gamma * x ** (n-index-1), x)
        v[0] = root.value
        # due to ECC:
        for i in range(1,6):
            v[i] = int(t/b)
        queries += 1
        output = FullOracle(version, v, U, S)
        if output == '-':
            root = root.left
        else:
            root = root.right
    return root.alpha, root.beta, root.gamma

# function that recovers the whole secret key
def Recover(root, S, version):
    q, p, t, b, n, h, mu = getParameters(version)
    recovered_secret = []
    for index in range(0,n-(n%3),3):
        #print('index: ' + str(int(index/3)))
        a, b, c = RecoverCoefficient(root, S, version, index)
        recovered_secret.append(a)
        recovered_secret.append(b)
        recovered_secret.append(c)
    return recovered_secret


# this implementation is quite slow because of the non-optimized polynomial multiplication
# when targeting the scheme in real, faster multiplication will be used
# this code is only to show that the attack works as described


# NIST security level 1:
queries = 0
version = 1
total = 1
correct = 0
q, p, t, b, n, h, mu = getParameters(version)
root = reconstruct(readjson('data\code_RLWR_1_3D.txt'))
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
print('RLWR with ECC, NIST level 1, dimension of the attack is 3')
print('Average number of queries to recover one secret coefficient: ' + str(queries / (total * n)))
print('Success probability: ' + str(100 * correct / total))
print('-----------------------------------------------------------------------------')


# NIST security level 3:
queries = 0
version = 3
total = 1
correct = 0
q, p, t, b, n, h, mu = getParameters(version)
root = reconstruct(readjson('data\code_RLWR_3_3D.txt'))
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
print('RLWR with ECC, NIST level 3, dimension of the attack is 3')
print('Average number of queries to recover one secret coefficient: ' + str(queries / (total * n)))
print('Success probability: ' + str(100 * correct / total))
print('-----------------------------------------------------------------------------')


# NIST security level 5:
queries = 0
version = 5
total = 1
correct = 0
q, p, t, b, n, h, mu = getParameters(version)
root = reconstruct(readjson('data\code_RLWR_5_3D.txt'))
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
print('RLWR with ECC, NIST level 5, dimension of the attack is 3')
print('Average number of queries to recover one secret coefficient: ' + str(queries / (total * n)))
print('Success probability: ' + str(100 * correct / total))
print('-----------------------------------------------------------------------------')
