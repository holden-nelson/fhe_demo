# TFHE Demo

TFHE is a c/c++ library for doing bitwise homomorphic encryption.

The `alice.c` file contains code for generating keys and encrypting data.

The `cloud.c` file performs operations on the data.

The `verif.c` file decrypts the results.

Compile with 
``` gcc alice.c -ltfhe-spqlios-fma ```
