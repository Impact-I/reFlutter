#!/usr/bin/env python3

"""
Get snapshot hash
"""

import re
import string
import sys


def usage():
    print('[-] Usage: python {} [lib_app_library]'.format(sys.argv[0]))
    sys.exit(1)


if len(sys.argv) != 2:
    usage()

fname = sys.argv[1]
min = 32
if sys.version_info >= (3, 0):
    f = open(fname, errors="ignore")
else:
    f = open(fname, 'rb')

libappHash = ""
result = ""
for c in f.read():
    if c in string.printable:
        result += c
        continue
    if len(result) >= min:
        hashT = re.findall(r"([a-f\d]{32})", result)
        if len(hashT) > 0:
            libappHash = hashT[0]
            break
        f.close()
    result = ""

print(libappHash)
