#!/usr/bin/env python3

"""
Get snapshot hash
"""
import re
import string
import sys

from requests import get


def usage():
    print('[-] Usage: python {} [flutter_engine_library]'.format(sys.argv[0]))
    sys.exit(1)


if len(sys.argv) != 2:
    usage()


def is_hash_valid(string_hash: str) -> bool:
    return get(f'https://github.com/flutter/engine/tree/{string_hash}').status_code == 200


fname = sys.argv[1]
min = 40
if sys.version_info >= (3, 0):
    f = open(fname, errors='ignore')
else:
    f = open(fname, 'rb')

libappHash = []
excluded_hashes = ['0000000000000000000000000000000000000000', '6666666666666660666666666666666666666666',
                   'a2a2a2a2a2a2aa4a2aa4a2aa4a2aa4a2aa4a2a2a', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                   'a2a2a2a2a2a2aa4a2aa4a2aa4a2aa4a2aa4a2a2a']
result = ''
counter = 0
for c in f.read():
    if c in string.printable:
        result += c
        continue
    if len(result) >= min:
        hashT = re.findall(r'([a-f\d]{40})', result)
        if len(hashT) == 1 and (hashT[0] not in excluded_hashes):
            libappHash.append(hashT[0])
        f.close()
    result = ''

for _hash in libappHash:
    if is_hash_valid(_hash):
        print(_hash)
