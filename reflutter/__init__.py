#!/usr/bin/env python3

import argparse
import os
import csv

try:
    from . import utils
except Exception:
    import utils

from urllib.request import urlretrieve
from zipfile import ZipFile
from os.path import join
import zipfile

# inits
patch_dump = False
build_engine = False


def _patch_file(file_name: str):
    print("[*] Processing...")
    zip_stored = False
    libapp_arm64 = "", ""
    libapp_arm = "", ""
    libapp_x86 = "", ""
    libapp_x64 = "", ""
    libapp_ios = "", ""
    libapp_hash = ""
    global patch_dump
    with ZipFile(file_name, "r") as zip_object:
        list_of_file_names = zip_object.namelist()
        zip_object.extractall("release")
        for file_name in list_of_file_names:
            if file_name.endswith("App.framework/App") or file_name.endswith(
                "FlutterApp.framework/FlutterApp"
            ):
                zip_object.extract(file_name, "libappTmp")
                libapp_ios = file_name, utils.elff(join("libappTmp", file_name))
                libapp_hash = libapp_ios[1]
            if file_name.endswith("v8a/libapp.so"):
                if zip_object.getinfo(file_name).compress_type == zipfile.ZIP_STORED:
                    zip_stored = True
                zip_object.extract(file_name, "libappTmp")
                libapp_arm64 = file_name, utils.elff(join("libappTmp", file_name))
                libapp_hash = libapp_arm64[1]
            if file_name.endswith("v7a/libapp.so"):
                if zip_object.getinfo(file_name).compress_type == zipfile.ZIP_STORED:
                    zip_stored = True
                zip_object.extract(file_name, "libappTmp")
                libapp_arm = file_name, utils.elff(join("libappTmp", file_name))
                libapp_hash = libapp_arm[1]
            if file_name.endswith("64/libapp.so"):
                if zip_object.getinfo(file_name).compress_type == zipfile.ZIP_STORED:
                    zip_stored = True
                zip_object.extract(file_name, "libappTmp")
                libapp_x64 = file_name, utils.elff(join("libappTmp", file_name))
                libapp_hash = libapp_arm[1]
            if file_name.endswith("86/libflutter.so"):
                zip_object.extract(file_name, "libappTmp")
                libapp_x86 = file_name, utils.elff(join("libappTmp", file_name))
                libapp_hash = libapp_arm[1]
        zip_object.close()
        utils.replace_flutter_lib(
            libapp_hash,
            libapp_arm64,
            libapp_arm,
            libapp_x64,
            libapp_x86,
            libapp_ios,
            zip_stored,
            patch_dump,
        )


def _build_engine(libapp_hash: str):
    global patch_dump
    if not os.path.exists("enginehash.csv"):
        urlretrieve(
            "https://raw.githubusercontent.com/Impact-I/reFlutter/main/enginehash.csv",
            "enginehash.csv",
        )

    with open("enginehash.csv") as f_obj:
        utils.replace_file_text(
            "src/src/flutter/BUILD.gn",
            '  if (is_android) {\n    public_deps +=\n        [ "//flutter/shell/platform/android:flutter_shell_native_unittests" ]\n  }',
            "",
        )
        read = csv.DictReader(f_obj, delimiter=",")
        row_count = sum(1 for _ in read)
        f_obj.seek(0)
        reader = csv.DictReader(f_obj, delimiter=",")
        i = -row_count
        for line in reader:
            i = i + 1
            if libapp_hash in line["Snapshot_Hash"]:
                print(line["Engine_commit"])
                if (
                    os.path.exists("src/third_party/dart/runtime/vm/dart.cc")
                    or os.path.exists("tools/generate_package_config/pubspec.yaml")
                    or os.path.exists("deps")
                    or os.path.exists("src/flutter/third_party/dart/runtime/vm/dart.cc")
                    or os.path.exists(
                        "engine/src/flutter/third_party/dart/runtime/vm/dart.cc"
                    )
                ):
                    utils.patch_source(libapp_hash, abs(i), patch_dump)


def main():
    global patch_dump, build_engine
    parser = argparse.ArgumentParser(description="reflutter")
    parser.add_argument(
        "-b",
        "--build-engine",
        help="Enable build engine",
    )
    parser.add_argument(
        "-p",
        "--patch-dump",
        action="store_true",
        default=False,
        help="Enable patch dump",
    )
    parser.add_argument("target", nargs="?", help="APK or IPA file")

    args = parser.parse_args()
    if args.build_engine:
        build_engine = True

    if args.patch_dump:
        patch_dump = True

    if build_engine:
        _build_engine(args.build_engine)
    else:
        if args.target:
            _patch_file(args.target)
        else:
            parser.print_usage()
