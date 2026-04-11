# X59 Format

## Standard

CLASSICALPK:PQPK/CLASSICALSK:PQSK

/ = delimiter for algorithms

Decision #1: CL_PK:CL_SK/PQ_PK:PQSK

//This one because it can keep the algorithms seperated and use standard colon syntax.

Decision #2: CL_PK:PQ_PK/CL_SK:PQ_SK

This decision was actually made due to API using colons to seperate public keys.

Pros:


- [X] Keeps public key together
- [X] Easily Split Public Key From Secret Key

Cons:
- [X] Does not follow standard of colon syntax
- [X] Algorithms are not the same