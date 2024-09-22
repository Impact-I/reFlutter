#!/usr/bin/env python3

"""
Get Snapshot Hash
"""

import re
import string
import sys


def usage():
    print('[-] Usage: python {} [libapp.so]'.format(sys.argv[0]))
    sys.exit(1)


if len(sys.argv) != 2:
    usage()

file_name = sys.argv[1]
min_hash_length = 32
if sys.version_info >= (3, 0):
    f = open(file_name, errors="ignore")
else:
    f = open(file_name, 'rb')

lib_app_hash = ""
result = ""
for c in f.read():
    if c in string.printable:
        result += c
        continue
    if len(result) >= min_hash_length:
        hashT = re.findall(r"([a-f\d]{32})", result)
        if len(hashT) > 0:
            lib_app_hash = hashT[0]
            break
        f.close()
    result = ""

print(lib_app_hash)
