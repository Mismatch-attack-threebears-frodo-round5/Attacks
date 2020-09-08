This repository contains supplementary material to the paper *Key Mismatch Attack on ThreeBears, Frodo and
Round5*.

There are three folders - *Frodo*, *Round5* and *ThreeBears* - each corresponding to the particular scheme. The folder *Round5* is further divided 
according to the variant it is based on.

Each of these folders contain several python scripts and a folder called *data*. The attack against ThreeBears is in python2 because the referenced implementation of ThreeBears is
in python2. Attacks against Round5 and Frodo are in python3. 

Folders called *data* contain the binary trees in a specific format defined in scripts called *BinaryTree?D.py*, where ? denotes the dimension of the attack. These scripts are also used to read the trees from the file. 

The attacks are then in scripts called *?D.py*, where ? denotes the dimension of the attack. Scripts called *Functions* contain functions used in the schemes and in the attack,
e.g. generation of secrets, decoding, oracle etc. 


