import json

# for the leaves, the variable value contains the secret coefficient
class Node:
    def __init__(self, id, left, right, value, alpha, beta):
        self.id = id
        self.left = left
        self.right = right
        self.value = value
        self.alpha = alpha
        self.beta = beta
        
length = 0
treearray = []
idcount = 0

def newnode(left, right, value, alpha, beta):
    global length
    length = length + 1
    node = Node(length, left, right, value, alpha, beta)
    return (node)

def newnodefromarray(node):
    result = newnode(None, None, node[3], node[4], node[5])
    return (result)

def reconstruct(nodes):
    global length
    length = 0
    nodearray = []
    for i in range(len(nodes)):
        nodearray.append(newnodefromarray(nodes[i]))
    for i in range(len(nodes)):
        nodearray[i].left = nodearray[nodes[i][1] - 1] if nodes[i][1] else None
        nodearray[i].right = nodearray[nodes[i][2] - 1] if nodes[i][2] else None
    return (nodearray[len(nodes) - 1])

def readjson(filename):
    with open(filename, "rb") as input:
        return (json.load(input))

