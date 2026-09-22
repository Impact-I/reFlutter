#!/usr/bin/env python3

"""
Get Snapshot Hash
"""

import os
import sys

sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/../reflutter")
from utils import elff


def usage():
    print("[-] Usage: python {} [libapp.so]".format(sys.argv[0]))
    sys.exit(1)


if len(sys.argv) != 2:
    usage()

print(elff(sys.argv[1]))
