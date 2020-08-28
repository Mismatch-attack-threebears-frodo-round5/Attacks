import json

# for leaves, value is the secret coeff
# changeable
class Node:
    def __init__(self, id, left, right, value, alpha, beta, gamma, delta):
        self.id = id
        self.left = left
        self.right = right
        self.value = value
        self.alpha = alpha
        self.beta = beta
        self.gamma = gamma
        self.delta = delta
    """
    def __str__(self):
        choices = "coeff=" + str(self.coeff) + "; \t l_j=[" + str(self.j0) + "," + str(self.j1) + "," + str(
            self.j2) + "," + str(self.j3) + "]" if self.left else "S_j=[" + str(self.j0) + "," + str(
            self.j1) + "," + str(self.j2) + "," + str(self.j3) + "]"
        children = "(" + (str(self.left.id) if self.left else "x") + "," + (
            str(self.right.id) if self.right else "x") + "),  \t" if self.left else " =>\t"
        return (str(self.id) + ": \t" + children + choices)
    """

# changeable
def Atojson(node):
    return ([node.id, node.left.id, node.right.id, node.value, node.alpha, node.beta, node.gamma, node.delta] if node.left else [
        node.id, None, None, node.value, node.alpha, node.beta, node.gamma, node.delta])

length = 0
treearray = []
idcount = 0

# changeable
def newnode(left, right, value, alpha, beta, gamma, delta):
    global length
    length = length + 1
    node = Node(length, left, right, value, alpha, beta, gamma, delta)
    return (node)

# changeable
def newnodefromarray(node):
    result = newnode(None, None, node[3], node[4], node[5], node[6], node[7])
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

def treetoarray(node):
    global treearray
    if (node.left == None):
        treearray.append(Atojson(node))
    else:
        treetoarray(node.left)
        treetoarray(node.right)
        treearray.append(Atojson(node))

def writejson(obj, filename):
    global treearray
    global idcount
    idcount = 1
    addid(obj)
    treearray = []
    treetoarray(obj)
    with open(filename, "w") as output:
        json.dump(treearray, output)

def readjson(filename):
    with open(filename, "rb") as input:
        return (json.load(input))

def printnodes(node):
    if (node.left == None):
        print(node)
    else:
        printnodes(node.left)
        printnodes(node.right)
        print(node)

def addid(node):
    global idcount
    if(node.left==None):
        node.id=idcount
        idcount=idcount+1
    else:
        addid(node.left)
        addid(node.right)
        node.id=idcount
        idcount=idcount+1