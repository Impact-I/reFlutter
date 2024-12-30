#!/usr/bin/env python3

"""
Get Flutter Engine Hash
"""

import re
import string
import sys

from requests import get


def usage():
    print("[-] Usage: python {} [libflutter.so]".format(sys.argv[0]))
    sys.exit(1)


if len(sys.argv) != 2:
    usage()


def is_hash_valid(string_hash: str) -> bool:
    return (
        get(f"https://github.com/flutter/engine/commit/{string_hash}").status_code
        == 200
    )


file_name = sys.argv[1]
min_hash_length = 40
f = open(file_name, errors="ignore")

lib_app_hash = []
excluded_hashes = [
    "0000000000000000000000000000000000000000",
    "6666666666666660666666666666666666666666",
    "a2a2a2a2a2a2aa4a2aa4a2aa4a2aa4a2aa4a2a2a",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "a2a2a2a2a2a2aa4a2aa4a2aa4a2aa4a2aa4a2a2a",
    "3333333333333333333333333333333333333333",
]
result = ""
counter = 0
for c in f.read():
    if c in string.printable:
        result += c
        continue
    if len(result) >= min_hash_length:
        hashT = re.findall(r"([a-f\d]{40})", result)
        for _hash in hashT:
            if _hash not in excluded_hashes:
                lib_app_hash.append(_hash)
        f.close()
    result = ""

for _hash in lib_app_hash:
    if is_hash_valid(_hash):
        print(_hash)
