#!/usr/bin/env python3

import csv

with open("enginehash.csv") as f_obj:
    read = csv.DictReader(f_obj, delimiter=',')
    row_count = sum(1 for _ in read)
    f_obj.seek(0)
    reader = csv.DictReader(f_obj, delimiter=',')
    i = -row_count
    for line in reader:
        i = i + 1
        print(abs(i), line['version'], line['Snapshot_Hash'])
