#!/usr/bin/env python3

import argparse
import os
import csv
import socket
import sys

try:
    from . import utils
except Exception:
    import utils

from urllib.request import urlretrieve
from zipfile import ZipFile
from os.path import join
import zipfile
import glob
import shutil

# every urlretrieve/urlopen in the package inherits this - without it a
# stalled connection hangs the tool forever (same bug class gen_enginehash had)
socket.setdefaulttimeout(60)

# inits
patch_dump = False
build_engine = False
no_interact = False


def _patch_file(file_name: str):
    print("[*] Processing...")
    # a leftover tree from a previous run would silently merge two different
    # apps into one package
    shutil.rmtree("release", ignore_errors=True)
    shutil.rmtree("libappTmp", ignore_errors=True)
    zip_stored = False
    libapp_arm64 = "", ""
    libapp_arm = "", ""
    libapp_x86 = "", ""
    libapp_x64 = "", ""
    libapp_ios = "", ""
    libapp_hash = ""
    global patch_dump
    global no_interact
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
                libapp_hash = libapp_x64[1]
            if file_name.endswith("86/libapp.so"):
                if zip_object.getinfo(file_name).compress_type == zipfile.ZIP_STORED:
                    zip_stored = True
                zip_object.extract(file_name, "libappTmp")
                libapp_x86 = file_name, utils.elff(join("libappTmp", file_name))
                libapp_hash = libapp_x86[1]
        zip_object.close()
        if not libapp_hash:
            # fallback: scan extracted release/ for libapp.so or App binaries
            candidates = (
                glob.glob("release/**/libapp.so", recursive=True)
                + glob.glob("release/**/App.framework/App", recursive=True)
                + glob.glob("release/**/FlutterApp.framework/FlutterApp", recursive=True)
            )
            for cand in candidates:
                if "arm64" in cand or "v8a" in cand:
                    libapp_arm64 = cand, utils.elff(cand)
                    libapp_hash = libapp_arm64[1]
                elif "armeabi" in cand or "v7a" in cand:
                    libapp_arm = cand, utils.elff(cand)
                    libapp_hash = libapp_arm[1]
                elif "x86_64" in cand:
                    libapp_x64 = cand, utils.elff(cand)
                    libapp_hash = libapp_x64[1]
                elif "x86" in cand:
                    libapp_x86 = cand, utils.elff(cand)
                    libapp_hash = libapp_x86[1]
                elif "App.framework" in cand or "FlutterApp.framework" in cand:
                    libapp_ios = cand, utils.elff(cand)
                    libapp_hash = libapp_ios[1]
                if libapp_hash:
                    break
        is_shorebird = any(
            fn.endswith("flutter_assets/shorebird.yaml")
            for fn in list_of_file_names
        )
        if is_shorebird:
            print("[*] Shorebird build detected (flutter_assets/shorebird.yaml)")
        utils.replace_flutter_lib(
            libapp_hash,
            libapp_arm64,
            libapp_arm,
            libapp_x64,
            libapp_x86,
            libapp_ios,
            zip_stored,
            patch_dump,
            no_interact,
            is_shorebird,
        )


def _build_engine(libapp_hash: str):
    global patch_dump
    if not os.path.exists("enginehash.csv"):
        urlretrieve(
            "https://raw.githubusercontent.com/Impact-I/reFlutter/main/enginehash.csv",
            "enginehash.csv",
        )

    # vanilla engines live in enginehash.csv, Shorebird engines in
    # enginehash_sb.csv - try both before giving up
    for csv_name in ("enginehash.csv", "enginehash_sb.csv", "enginehash_profile.csv"):
        if csv_name != "enginehash.csv" and not os.path.exists(csv_name):
            try:
                urlretrieve(
                    "https://raw.githubusercontent.com/Impact-I/reFlutter/main/"
                    + csv_name,
                    csv_name,
                )
            except Exception:
                continue
        if not os.path.exists(csv_name):
            continue

        with open(csv_name) as f_obj:
            reader = csv.DictReader(f_obj, delimiter=",")
            rows = list(reader)
        for idx, line in enumerate(rows):
            if libapp_hash in line["Snapshot_Hash"]:
                print(line["Engine_commit"])
                if csv_name == "enginehash_sb.csv":
                    flavor_note = " (Shorebird row)"
                    # ver indexes row position, which is chronological in
                    # enginehash.csv but ALPHABETICAL in the sb csv - sb
                    # engines are all modern-era, so use the newest-ver
                    # patch branches. Older sb engines whose anchors moved
                    # fail loudly in local-release verify_patches.
                    ver = max(len(rows) - idx - 1, 55)
                else:
                    flavor_note = ""
                    ver = len(rows) - idx - 1
                # diagnostics to stderr - local-release parses stdout for the commit
                dart_version = (line.get("Dart_Version") or "").strip()
                print(
                    "matched " + csv_name + flavor_note + ", ver " + str(ver)
                    + (", dart " + dart_version if dart_version else ""),
                    file=sys.stderr,
                )
                if (
                    os.path.exists("src/third_party/dart/runtime/vm/dart.cc")
                    or os.path.exists("tools/generate_package_config/pubspec.yaml")
                    or os.path.exists("deps")
                    or os.path.exists("src/flutter/third_party/dart/runtime/vm/dart.cc")
                    or os.path.exists(
                        "engine/src/flutter/third_party/dart/runtime/vm/dart.cc"
                    )
                ):
                    utils.patch_source(libapp_hash, ver, patch_dump, dart_version)
                return

    print(
        "\n SnapshotHash "
        + libapp_hash
        + " not found in enginehash.csv or enginehash_sb.csv.\n"
        " Run scripts/gen_enginehash.py (or --shorebird) to refresh the lists.\n"
    )
    sys.exit(1)


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
    parser.add_argument(
        "-n",
        "--no-interact",
        action="store_true",
        default=False,
        help="Skip Burp IP prompt (uses 127.0.0.1 for old engines)",
    )
    parser.add_argument("target", nargs="?", help="APK or IPA file")

    args = parser.parse_args()
    if args.build_engine:
        build_engine = True

    if args.patch_dump:
        patch_dump = True

    if args.no_interact:
        no_interact = True

    if build_engine:
        _build_engine(args.build_engine)
    else:
        if args.target:
            _patch_file(args.target)
        else:
            parser.print_usage()
