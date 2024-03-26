#!/usr/bin/env python3

import os
import subprocess
from os.path import isfile, isdir
from shutil import rmtree
from urllib.request import urlretrieve
from zipfile import ZipFile

from requests import get

from src import ELFF

release_url = 'https://storage.googleapis.com/flutter_infra_release/releases/releases_linux.json'
snapshot_url = 'https://storage.googleapis.com/flutter_infra_release/flutter/{}/android-arm64-release/linux-x64.zip'
log_file_path = 'enginehash.tmp'
log_file_final = 'enginehash.tmp.csv'
flutter_path = './flutter'


def log_file(log_data):
    with open(log_file_path, 'a') as lf:
        lf.write(log_data)


def cli(command):
    p = subprocess.Popen(command, stdout=subprocess.PIPE)
    return p.stdout.read().decode()


def get_snapshot_hash(engine_hash: str) -> str | None:
    try:
        zip_file_path = '/tmp/{}.zip'.format(engine_hash)
        engine_hash_path = '/tmp/{}'.format(engine_hash)
        urlretrieve(snapshot_url.format(engine_hash), zip_file_path)
        with ZipFile(zip_file_path, 'r') as zipObject:
            listOfFileNames = zipObject.namelist()
            zipObject.extractall(engine_hash_path)
        gen_snapshot_file_path = '{}/gen_snapshot'.format(engine_hash_path)
        if isfile(gen_snapshot_file_path):
            lib_app_hash = ELFF(gen_snapshot_file_path)
            os.remove(zip_file_path)
            rmtree(engine_hash_path)
            return lib_app_hash
        return None
    except Exception as e:
        print(str(e) + ' => ' + engine_hash)
        return None


# main
with open(log_file_path, 'w') as f:
    f.write('version,Engine_commit,Snapshot_Hash\n')

if isdir(flutter_path):
    rmtree(flutter_path)

cli(['git', 'clone', 'https://github.com/flutter/flutter.git', flutter_path])

if isdir(flutter_path):
    for data in get(release_url).json()['releases']:
        _engine_hash = data['hash']
        engine = cli(['./gen_enginehash.sh', _engine_hash]).rstrip().strip()
        data['engine_commit'] = engine
        print(data)
        data['snapshot_hash'] = get_snapshot_hash(data['engine_commit'])
        if data['snapshot_hash'] is not None:
            log_data = '{},{},{}\n'.format(data['version'], data['engine_commit'], data['snapshot_hash'])
            log_file(log_data)
            print(log_data)

    # save file
    cli(['mv', log_file_path, log_file_final])
