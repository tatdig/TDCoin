#!/usr/bin/env python
#
# a simple filter that reads 64 HEX chars on each line stdin and outputs the WIF format on stdout
# good for bulk conversion of random data into Bitcoin private keys
#.
# eg. hexdump -v -e '/1 "%02X"' -n 32 /dev/urandom | hexwif
# example priv_key 0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D
# TDCOIN 6b

import sys, binascii, hashlib

for line in sys.stdin:
<------>line = line[:64]
<------>alphabet="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
<------>chksum = binascii.hexlify(hashlib.sha256(hashlib.sha256(binascii.unhexlify('6b'+line)).digest()).digest()[:4])
<------>bn = long('6b'+line+chksum, 16)
<------>
<------>out = ""
<------>while bn >= 58:
<------><------>bn,m = divmod(bn, 58)
<------><------>out = alphabet[m] + out
<------>print alphabet[bn] + out
