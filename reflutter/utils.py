#!/usr/bin/env python3

import os
import shutil
import sys
from urllib.request import urlopen, urlretrieve
from os.path import join
import zipfile
import string
import re

OLD_SOCKET_PATCH_LAST_VERSION = 58

SHOREBIRD_ARTIFACT_URL = (
    "https://storage.googleapis.com/download.shorebird.dev/flutter_infra_release"
    "/flutter/{engine}/{artifact}/artifacts.zip"
)
# arm64: mov w0, #1 ; ret  - makes boringssl's certificate-chain
# verification succeed unconditionally (traffic interception without
# touching the app's snapshot format)
VERIFY_BYPASS_ARM64 = bytes.fromhex("20008052" "c0035fd6")


def patch_engine_verify(data: bytes) -> bytes:
    """Return a copy of an engine ELF with boringssl's
    ssl_crypto_x509_session_verify_cert_chain patched to return true.

    Walks the ELF in pure Python (no external tooling): program headers map
    symbol addresses to file offsets, the symbol table provides the address.
    Afterwards everything after the last PT_LOAD is dropped and the section
    table is zeroed - Android's linker only reads program headers, so this
    strips Shorebird's ~150MB of shipped symbols safely."""
    import struct

    if data[:4] != b"\x7fELF" or data[4] != 2:
        raise ValueError("expected a 64-bit ELF engine library")
    endian = "<" if data[5] == 1 else ">"

    def u16(off):
        return struct.unpack_from(endian + "H", data, off)[0]

    def u32(off):
        return struct.unpack_from(endian + "I", data, off)[0]

    def u64(off):
        return struct.unpack_from(endian + "Q", data, off)[0]

    e_phoff, e_shoff = u64(0x20), u64(0x28)
    e_phentsize, e_phnum = u16(0x36), u16(0x38)
    e_shentsize, e_shnum, e_shstrndx = u16(0x3A), u16(0x3C), u16(0x3E)

    segments = []
    for i in range(e_phnum):
        b = e_phoff + i * e_phentsize
        if u32(b) == 1:  # PT_LOAD
            segments.append((u64(b + 16), u64(b + 8), u64(b + 32)))  # vaddr, off, size

    def vaddr_to_off(v):
        for vaddr, offset, filesz in segments:
            if vaddr <= v < vaddr + filesz:
                return offset + (v - vaddr)
        raise ValueError("symbol address is not backed by a PT_LOAD segment")

    sections = []
    for i in range(e_shnum):
        b = e_shoff + i * e_shentsize
        sections.append((u32(b), u32(b + 4), u64(b + 24), u64(b + 32)))
    shstr_off = sections[e_shstrndx][2]
    symtab = strtab = symtab_size = None
    for name_idx, sh_type, off, size in sections:
        end = data.index(b"\0", shstr_off + name_idx)
        name = data[shstr_off + name_idx : end].decode()
        if name == ".symtab" and sh_type == 2:
            symtab, symtab_size = off, size
        elif name == ".strtab" and sh_type == 3:
            strtab = off
    if symtab is None or strtab is None:
        raise ValueError(
            "engine ELF carries no symbol table - pattern-based patching not implemented"
        )

    target = b"ssl_crypto_x509_session_verify_cert_chain"
    out = bytearray(data)
    entry = 24  # Elf64_Sym
    for i in range(symtab_size // entry):
        b = symtab + i * entry
        st_name = u32(b)
        if not st_name:
            continue
        name_end = data.index(b"\0", strtab + st_name)
        if target in data[strtab + st_name : name_end]:
            off = vaddr_to_off(u64(b + 8))
            out[off : off + 8] = VERIFY_BYPASS_ARM64
            # drop everything past the last PT_LOAD and void the section table
            tail = max(offset + filesz for _, offset, filesz in segments)
            struct.pack_into(endian + "Q", out, 0x28, 0)  # e_shoff = 0
            struct.pack_into(endian + "H", out, 0x3C, 0)  # e_shnum = 0
            return bytes(out[:tail])
    raise ValueError("verify_cert_chain symbol not found in engine")


def patch_engine_verify_macho(data: bytes) -> bytes:
    """Mach-O arm64 twin of patch_engine_verify, for iOS Flutter frameworks.

    Walks LC_SEGMENT_64 (vmaddr -> fileoff) and LC_SYMTAB in pure Python and
    patches boringssl's certificate-chain verification to return true. Fat
    binaries are handled by patching every arm64 slice."""
    import struct

    def patch_thin(slice_data: bytes) -> bytes:
        if struct.unpack_from("<I", slice_data, 0)[0] != 0xFEEDFACF:
            raise ValueError("expected an arm64 Mach-O slice")
        ncmds = struct.unpack_from("<I", slice_data, 16)[0]
        off = 32
        segments = []
        symtab = None
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from("<II", slice_data, off)
            if cmd == 0x19:  # LC_SEGMENT_64
                segname = slice_data[off + 8 : off + 24].rstrip(b"\0")
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from(
                    "<QQQQ", slice_data, off + 24
                )
                if filesize:
                    segments.append((segname, vmaddr, vmsize, fileoff))
            elif cmd == 0x2:  # LC_SYMTAB
                symtab = struct.unpack_from("<IIII", slice_data, off + 8)
            off += cmdsize
        if symtab is None:
            raise ValueError(
                "Mach-O carries no symbol table - stripped iOS artifacts need "
                "pattern-based patching (pending)"
            )
        symoff, nsyms, stroff, _strsize = symtab

        def vaddr_to_off(v):
            for _, vmaddr, vmsize, fileoff in segments:
                if vmaddr <= v < vmaddr + vmsize:
                    return fileoff + (v - vmaddr)
            raise ValueError("symbol address outside all segments")

        target = b"ssl_crypto_x509_session_verify_cert_chain"
        out = bytearray(slice_data)
        for i in range(nsyms):
            b = symoff + i * 16  # nlist_64
            n_strx = struct.unpack_from("<I", out, b)[0]
            if not n_strx:
                continue
            name_end = out.index(b"\0", stroff + n_strx)
            if target in out[stroff + n_strx : name_end]:
                n_value = struct.unpack_from("<Q", out, b + 8)[0]
                off = vaddr_to_off(n_value)
                out[off : off + 8] = VERIFY_BYPASS_ARM64
                return bytes(out)
        raise ValueError(
            "verify_cert_chain symbol not found - Shorebird iOS artifacts are "
            "stripped of local symbols; pattern-based patching is pending"
        )

    magic_be = struct.unpack_from(">I", data, 0)[0]
    if magic_be == 0xCAFEBABE:  # fat binary - patch each arm64 slice
        nfat = struct.unpack_from(">I", data, 4)[0]
        out = bytearray(data)
        for i in range(nfat):
            b = 8 + i * 20  # fat_arch
            cputype, _, offset, size, _ = struct.unpack_from(">IIIII", data, b)
            if cputype == 0x0100000C:  # CPU_TYPE_ARM64
                out[offset : offset + size] = patch_thin(data[offset : offset + size])
        return bytes(out)
    return patch_thin(data)


def fetch_shorebird_engine(engine_commit: str, dest_path: str, arch: str):
    """Download Shorebird's own engine artifact for this revision, patch its
    certificate verification, and write it to dest_path. Using their binary
    sidesteps their private Dart fork entirely - their engine loads their
    snapshot format, we only defang TLS validation."""
    import io

    artifacts = {
        "arm64": "android-arm64-release",
        "arm": "android-arm-release",
        "x64": "android-x64-release",
        "ios": "ios-release",
    }
    url = SHOREBIRD_ARTIFACT_URL.format(
        engine=engine_commit, artifact=artifacts[arch]
    )
    raw = urlopen(url).read()
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        names = archive.namelist()
        if arch == "ios":
            member = next(n for n in names if n.endswith("Flutter.framework/Flutter"))
            engine = archive.read(member)
            patched = patch_engine_verify_macho(engine)
            with open(dest_path, "wb") as f:
                f.write(patched)
            return dest_path
        if "flutter.jar" in names:
            # android artifacts nest the engine inside the embedding jar
            with zipfile.ZipFile(io.BytesIO(archive.read("flutter.jar"))) as jar:
                member = next(n for n in jar.namelist() if n.endswith("libflutter.so"))
                engine = jar.read(member)
        else:
            member = next(n for n in names if n.endswith("libflutter.so"))
            engine = archive.read(member)
    patched = patch_engine_verify(engine)
    with open(dest_path, "wb") as f:
        f.write(patched)
    return dest_path


def replace_file_text(fname, textOrig, textReplace):
    if fname[:15] == "src/third_party":  # fix for new flutter source path
        if not os.path.exists(fname):
            new_third_party_path = "src/flutter/" + "/".join(fname.split("/")[1:])
            if os.path.exists(new_third_party_path):
                fname = new_third_party_path
            else:
                # https://github.com/flutter/flutter/tree/master/engine
                fname = "engine/src/flutter/" + "/".join(fname.split("/")[1:])
    try:
        with open(fname, "r") as file:
            filedata = file.read()
            filedata = filedata.replace(textOrig, textReplace)
        with open(fname, "w") as file:
            file.write(filedata)
    except (IOError, OSError):
        pass


def zip_dir(path: str, ziph: zipfile.ZipFile, zip_stored: bool):
    for root, _, files in os.walk(path):
        for file in files:
            if type(file) is str:
                if (
                    file.endswith(".so")
                    and zip_stored
                    or file.endswith("resources.arsc")
                ):
                    ziph.write(
                        os.path.join(root, file),
                        os.path.relpath(
                            os.path.join(root.replace("release/", ""), file),
                            os.path.join(path, ".."),
                        ),
                        zipfile.ZIP_STORED,
                    )
                else:
                    ziph.write(
                        os.path.join(root, file),
                        os.path.relpath(
                            os.path.join(root.replace("release/", ""), file),
                            os.path.join(path, ".."),
                        ),
                        zipfile.ZIP_DEFLATED,
                    )
            else:
                ziph.write(
                    os.path.join(root, file),
                    os.path.relpath(
                        os.path.join(root.replace("release/", ""), file),
                        os.path.join(path, ".."),
                    ),
                    zipfile.ZIP_DEFLATED,
                )


def check_libapp_hash(libapp_hash: str, shorebird_hint: bool = False):
    """Resolve a snapshot hash against the engine CSVs.

    Returns (version_index, engine_commit, is_shorebird). A hash found only
    in enginehash_sb.csv identifies a Shorebird-built app even when the
    shorebird.yaml marker is absent (plain fork builds do not ship it)."""
    if libapp_hash == "":
        print(
            "\nIs this really a Flutter app? \nThere was no libapp.so (Android) or App (iOS) found in the package.\n\n Make sure there is arm64-v8a/libapp.so or App.framework/App file in the package. If flutter library name differs you need to rename it properly before patching.\n"
        )
        sys.exit(1)
    order = (
        ("enginehash_sb.csv", "enginehash.csv")
        if shorebird_hint
        else ("enginehash.csv", "enginehash_sb.csv")
    )
    for csv_name in order:
        try:
            resp = (
                urlopen(
                    "https://raw.githubusercontent.com/Impact-I/reFlutter/main/"
                    + csv_name
                )
                .read()
                .decode("utf-8")
            )
        except Exception:
            continue
        if libapp_hash not in resp:
            continue
        resp = resp.splitlines()
        _index = 0
        for _ in resp:
            _index += 1
            if libapp_hash in _:
                break
        engine_commit = resp[_index - 1].split(",")[1]
        is_sb = csv_name == "enginehash_sb.csv"
        if is_sb:
            print("[*] Shorebird engine identified (enginehash_sb.csv)")
        return len(resp) + 1 - _index, engine_commit, is_sb

    shutil.rmtree("libappTmp", ignore_errors=True)
    shutil.rmtree("release", ignore_errors=True)
    print(
        "\n Engine SnapshotHash: "
        + libapp_hash
        + "\n\n This engine is currently not supported.\n Most likely this flutter application uses the Debug version engine which you need to build manually using Docker at the moment,\n or a Shorebird engine newer than our collected list (run scripts/gen_enginehash.py --shorebird to refresh).\n More details: https://github.com/Impact-I/reFlutter\n"
    )
    sys.exit(1)


# Byte-level form of the scan elff() used to run char-by-char: find runs of
# printable ASCII >= 32 bytes, return the first 32-char lowercase-hex string
# inside one (the engine's expected snapshot hash). Same first-match
# semantics, but a regex over bytes instead of a Python loop over millions of
# decoded characters.
_PRINTABLE_RUN = re.compile(rb"[\x20-\x7e\t\n\r\x0b\x0c]{32,}")
_SNAPSHOT_HASH = re.compile(rb"[a-f\d]{32}")


def elff(fname: str) -> str:
    with open(fname, "rb") as f:
        for run in _PRINTABLE_RUN.finditer(f.read()):
            match = _SNAPSHOT_HASH.search(run.group())
            if match:
                return match.group().decode("ascii")
    return ""


def not_except(filename: str):
    try:
        os.remove(filename)
    except Exception:
        pass


def convert_ip_fix(IPBurp: str):
    intoct = list(IPBurp.split("."))
    finallistIP = list(IPBurp.split("."))
    intoct.sort(key=lambda s: len(s))
    intoct.reverse()
    for i in intoct:
        if (
            len(i) != 3 and int(i) > 7 and int(i) > 63 and len(".".join(intoct)) < 15
        ):  # 64-99
            intoct[intoct.index(i)] = str(oct(int(i))).replace("o", "")
        elif len(i) != 3 and 7 < int(i) < 64 and len(".".join(intoct)) < 15:  # 8-63
            intoct[intoct.index(i)] = str(oct(int(i))).replace("o", "")
        elif len(i) < 3 and int(i) < 8 and len(".".join(intoct)) < 15:  # 0-7
            intoct[intoct.index(i)] = intoct[intoct.index(i)].zfill(3)
    for i in intoct:
        if i.startswith("0"):
            if len(i) != 3 and int(i, 8) > 7 and len(".".join(intoct)) > 15:  # 8-63
                intoct[intoct.index(i)] = str(int(i, 8)).replace("o", "")
            elif len(i) < 3 and int(i) < 8 and len(".".join(intoct)) < 15:  # 0-7
                intoct[intoct.index(i)] = intoct[intoct.index(i)].zfill(3)
        elif (
            len(i) == 3 and int(i) > 7 and int(i) > 99 and len(".".join(intoct)) > 15
        ):  # 64-99
            intoct[intoct.index(i)] = str(oct(int(i))).replace("o", "")
    for i in intoct:
        nn = intoct.index(i)
        if i.startswith("0"):
            if len(i) > 2 and int(i) > 7 and len(".".join(intoct)) > 15:  # 8-63
                intoct[nn] = str(int(i, 8)).replace("o", "")
        elif (
            len(i) != 3 and int(i) > 7 and int(i) > 63 and len(".".join(intoct)) < 15
        ):  # 0-7
            intoct[nn] = str(oct(int(i))).replace("o", "")
    for i in intoct:
        if len(i) < 3 and int(i) < 8 and len(".".join(intoct)) < 15:
            intoct[intoct.index(i)] = str(int(i)).zfill(2)
    for f in finallistIP:
        for i in intoct:
            if i.startswith("0"):
                if f == str(int(i, 8)):
                    mi = finallistIP.index(f)
                    finallistIP[mi] = i.replace("o", "")
                    if len(".".join(finallistIP)) > 15:
                        finallistIP[mi] = str(int(i, 8)).replace("o", "")
    if len(".".join(finallistIP)) < 15:
        for f in finallistIP:
            if len(f) < 3 and int(f) < 8:
                finallistIP[finallistIP.index(f)] = str(int(f)).zfill(2)
    return ".".join(finallistIP)


def input_burp_ip() -> str:
    while True:
        burp_ip = input("\nExample: (192.168.1.154) etc.\nPlease enter your BurpSuite IP: ")
        if re.fullmatch(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}", burp_ip) and all(
            0 <= int(octet) <= 255 for octet in burp_ip.split(".")
        ):
            break
        print("Invalid IP Address")
    return convert_ip_fix(burp_ip)


def replace_flutter_lib(
    libapp_hash: str,
    libapp_arm64: tuple,
    libapp_arm: tuple,
    libapp_x64: tuple,
    libapp_x86: tuple,
    libapp_ios: tuple,
    zip_stored: bool,
    patch_dump: bool,
    no_interact: bool = False,
    shorebird: bool = False,
):
    flutter_version_index, engine_commit, shorebird = check_libapp_hash(
        libapp_hash, shorebird
    )

    burp_ip = None
    if (
        not shorebird
        and flutter_version_index is not None
        and flutter_version_index <= OLD_SOCKET_PATCH_LAST_VERSION
    ):
        if no_interact:
            # must be exactly 15 chars like the hardcoded placeholder in the
            # engine binary - convert_ip_fix guarantees that ("127.000.000.001")
            burp_ip = convert_ip_fix("127.0.0.1")
        else:
            burp_ip = input_burp_ip()
    get_network_lib(
        libapp_arm64,
        libapp_arm,
        libapp_x64,
        libapp_x86,
        libapp_ios,
        patch_dump,
        burp_ip,
        shorebird,
        engine_commit,
    )
    if (
        not os.path.exists("libflutter_arm64.so")
        and not os.path.exists("libflutter_arm.so")
        and not os.path.exists("libflutter_x64.so")
        and not os.path.exists("libflutter_x86.so")
        and not os.path.exists("Flutter")
    ):
        # Every engine variant download failed - without this check the app
        # would be re-zipped silently with its ORIGINAL (unpatched) engine.
        shutil.rmtree("libappTmp", ignore_errors=True)
        shutil.rmtree("release", ignore_errors=True)
        print(
            "\n SnapshotHash: "
            + libapp_hash
            + "\n\n Could not download any patched engine library for this version.\n"
            " The release assets may be missing or not yet uploaded for this engine"
            " (android-"
            + ("v3-" if patch_dump else "v2-")
            + libapp_hash
            + ").\n"
        )
        sys.exit(1)
    if (
        os.path.exists("libflutter_arm64.so")
        or os.path.exists("libflutter_arm.so")
        or os.path.exists("libflutter_x64.so")
        or os.path.exists("libflutter_x86.so")
        or os.path.exists("Flutter")
    ):
        missing_variants = [
            name
            for name, tup, lib in (
                ("ios", libapp_ios, "Flutter"),
                ("arm64", libapp_arm64, "libflutter_arm64.so"),
                ("arm", libapp_arm, "libflutter_arm.so"),
                ("x64", libapp_x64, "libflutter_x64.so"),
                ("x86", libapp_x86, "libflutter_x86.so"),
            )
            if len(tup[1]) != 0 and not os.path.exists(lib)
        ]
        if missing_variants:
            print(
                "\n[!] WARNING: no patched engine downloaded for: "
                + ", ".join(missing_variants)
                + " - those variants keep the ORIGINAL engine in the repacked package.\n"
            )
        try:
            shutil.move(
                "Flutter",
                join(
                    "release",
                    libapp_ios[0]
                    .replace("App.framework/App", "Flutter.framework/Flutter")
                    .replace(
                        "FlutterApp.framework/FlutterApp", "Flutter.framework/Flutter"
                    ),
                ),
            )
        except Exception:
            pass
        try:
            shutil.move(
                "libflutter_arm64.so",
                join("release", libapp_arm64[0].replace("libapp.so", "libflutter.so")),
            )
        except Exception:
            pass
        try:
            shutil.move(
                "libflutter_arm.so",
                join("release", libapp_arm[0].replace("libapp.so", "libflutter.so")),
            )
        except Exception:
            pass
        try:
            shutil.move(
                "libflutter_x64.so",
                join("release", libapp_x64[0].replace("libapp.so", "libflutter.so")),
            )
        except Exception:
            pass
        try:
            shutil.move("libflutter_x86.so", join("release", libapp_x86[0]))
        except Exception:
            pass

        zipf = zipfile.ZipFile("release.RE.zip", "w", zipfile.ZIP_DEFLATED)
        zip_dir("release/", zipf, zip_stored)
        zipf.close()
        shutil.rmtree("libappTmp", ignore_errors=True)
        shutil.rmtree("release", ignore_errors=True)
        print("\nSnapshotHash: " + libapp_hash)
        if len(libapp_ios[1]) != 0:
            shutil.move("release.RE.zip", "release.RE.ipa")
            print("The resulting ipa file: ./release.RE.ipa")
            if (
                shorebird
                or (
                    flutter_version_index is not None
                    and flutter_version_index > OLD_SOCKET_PATCH_LAST_VERSION
                )
            ):
                print(
                    "Please sign & install the ipa file.\n\nConfigure Potatso (iOS) to use your Burp Suite proxy server.\n"
                )
            else:
                print(
                    "Please sign & install the ipa file\n\nConfigure Burp Suite proxy server to listen on *:8083\nProxy Tab -> Options -> Proxy Listeners -> Edit -> Binding Tab\n\nThen enable invisible proxying in Request Handling Tab\nSupport Invisible Proxying -> true\n"
                )
        else:
            shutil.move("release.RE.zip", "release.RE.apk")
            print("The resulting apk file: ./release.RE.apk")
            if (
                shorebird
                or (
                    flutter_version_index is not None
                    and flutter_version_index > OLD_SOCKET_PATCH_LAST_VERSION
                )
            ):
                print(
                    "Please sign, align & install the apk file.\n\nConfigure TunProxy (Android) to use your Burp Suite proxy server.\n"
                )
            else:
                print(
                    "Please sign, align & install the apk file\n\nConfigure Burp Suite proxy server to listen on *:8083\nProxy Tab -> Options -> Proxy Listeners -> Edit -> Binding Tab\n\nThen enable invisible proxying in Request Handling Tab\nSupport Invisible Proxying -> true\n"
                )
        sys.exit()


def get_network_lib(
    libapp_arm64: tuple,
    libapp_arm: tuple,
    libapp_x64: tuple,
    libapp_x86: tuple,
    libapp_ios: tuple,
    patch_dump: bool,
    burp_ip: str | None,
    shorebird: bool = False,
    engine_commit: str = "",
):
    if shorebird:
        # Shorebird apps cannot use our engines (their snapshot format needs
        # their private Dart fork's loader). Instead we take Shorebird's own
        # engine artifact from their public bucket and patch boringssl's
        # certificate-chain verification to succeed unconditionally.
        for tup, lib, arch in (
            (libapp_arm64, "libflutter_arm64.so", "arm64"),
            (libapp_arm, "libflutter_arm.so", "arm"),
            (libapp_x64, "libflutter_x64.so", "x64"),
        ):
            if len(tup[1]) != 0:
                try:
                    print("[*] Shorebird: fetching + patching engine (" + arch + ") ...")
                    fetch_shorebird_engine(engine_commit, lib, arch)
                except Exception as error:
                    print(
                        "[!] Shorebird engine patching failed for "
                        + arch
                        + ": "
                        + repr(error)
                    )
        if len(libapp_ios[1]) != 0:
            try:
                print("[*] Shorebird: fetching + patching engine (iOS) ...")
                fetch_shorebird_engine(engine_commit, "Flutter", "ios")
            except Exception as error:
                print(
                    "[!] Shorebird iOS engine patching failed: " + repr(error)
                )
        return

    verUrl = "v3-" if patch_dump else "v2-"
    if len(libapp_ios[1]) != 0:
        try:
            urlretrieve(
                "https://github.com/Impact-I/reFlutter/releases/download/ios-"
                + verUrl
                + libapp_ios[1]
                + "/Flutter",
                "Flutter",
            )
        except Exception:
            libapp_ios = "", ""
            not_except("Flutter")
    if len(libapp_arm64[1]) != 0:
        try:
            urlretrieve(
                "https://github.com/Impact-I/reFlutter/releases/download/android-"
                + verUrl
                + libapp_arm64[1]
                + "/libflutter_arm64.so",
                "libflutter_arm64.so",
            )
        except Exception:
            libapp_arm64 = "", ""
            not_except("libflutter_arm64.so")
    if len(libapp_arm[1]) != 0:
        try:
            urlretrieve(
                "https://github.com/Impact-I/reFlutter/releases/download/android-"
                + verUrl
                + libapp_arm[1]
                + "/libflutter_arm.so",
                "libflutter_arm.so",
            )
        except Exception:
            libapp_arm = "", ""
            not_except("libflutter_arm.so")
    if len(libapp_x64[1]) != 0:
        try:
            urlretrieve(
                "https://github.com/Impact-I/reFlutter/releases/download/android-"
                + verUrl
                + libapp_x64[1]
                + "/libflutter_x64.so",
                "libflutter_x64.so",
            )
        except Exception:
            libapp_x64 = "", ""
            not_except("libflutter_x64.so")
    if len(libapp_x86[1]) != 0:
        try:
            urlretrieve(
                "https://github.com/Impact-I/reFlutter/releases/download/android-"
                + verUrl
                + libapp_x86[1]
                + "/libflutter_x86.so",
                "libflutter_x86.so",
            )
        except Exception:
            libapp_x86 = "", ""
            not_except("libflutter_x86.so")

    if burp_ip is not None:
        patch_library(
            libapp_arm64, libapp_arm, libapp_x64, libapp_x86, libapp_ios, burp_ip
        )


def patch_library(
    libapp_arm64: tuple,
    libapp_arm: tuple,
    libapp_x64: tuple,
    libapp_x86: tuple,
    libapp_ios: tuple,
    burp_ip: str,
):
    if burp_ip is not None and len(burp_ip) != 15:
        # the placeholder "192.168.133.104" in the engine binary is exactly 15
        # bytes; a different-length replacement would shift every byte after it
        # and corrupt the library
        print(
            "\n[!] Internal error: proxy IP '{}' is {} bytes, need exactly 15.\n".format(
                burp_ip, len(burp_ip)
            )
        )
        sys.exit(1)
    if len(libapp_ios[1]) != 0:
        buffer = (
            open("Flutter", "rb")
            .read()
            .replace(b"192.168.133.104", burp_ip.encode("ascii"))
        )
        open("Flutter", "wb").write(buffer)
    if len(libapp_arm64[1]) != 0:
        buffer = (
            open("libflutter_arm64.so", "rb")
            .read()
            .replace(b"192.168.133.104", burp_ip.encode("ascii"))
        )
        open("libflutter_arm64.so", "wb").write(buffer)
    if len(libapp_arm[1]) != 0:
        buffer = (
            open("libflutter_arm.so", "rb")
            .read()
            .replace(b"192.168.133.104", burp_ip.encode("ascii"))
        )
        open("libflutter_arm.so", "wb").write(buffer)
    if len(libapp_x64[1]) != 0:
        buffer = (
            open("libflutter_x64.so", "rb")
            .read()
            .replace(b"192.168.133.104", burp_ip.encode("ascii"))
        )
        open("libflutter_x64.so", "wb").write(buffer)
    if len(libapp_x86[1]) != 0:
        buffer = (
            open("libflutter_x86.so", "rb")
            .read()
            .replace(b"192.168.133.104", burp_ip.encode("ascii"))
        )
        open("libflutter_x86.so", "wb").write(buffer)


def patch_source(libapp_hash: str, ver: int, patch_dump: bool):
    try:
        os.makedirs(os.path.join(os.environ["HOME"], "Documents"))
    except Exception:
        pass
    try:
        os.makedirs("Documents")
    except Exception:
        pass
    replace_file_text(
        "DEPS",
        "'src/third_party/dart/third_party/pkg/stagehand':\n   Var('dart_git') + '/stagehand.git@e64ac90cac508981011299c4ceb819149e71f1bd',",
        "",
    )
    replace_file_text(
        "DEPS",
        "'src/third_party/dart/third_party/pkg/stagehand':\n   Var('dart_git') + '/stagehand.git' + '@' + Var('dart_stagehand_tag'),",
        "",
    )
    replace_file_text(
        "DEPS",
        "'src/third_party/dart/third_party/pkg/tflite_native':\n   Var('dart_git') + '/tflite_native.git' + '@' + Var('dart_tflite_native_rev'),",
        "",
    )
    replace_file_text(
        "src/third_party/dart/DEPS",
        'Var("dart_root") + "/third_party/pkg/tflite_native":\n      Var("dart_git") + "tflite_native.git" + "@" + Var("tflite_native_rev"),',
        "",
    )
    replace_file_text(
        "DEPS",
        'Var("dart_root") + "/third_party/pkg/tflite_native":\n      Var("dart_git") + "tflite_native.git" + "@" + Var("tflite_native_rev"),',
        "",
    )

    if ver >= 24 and patch_dump:
        replace_file_text(
            "src/third_party/dart/runtime/vm/clustered_snapshot.cc",
            "monomorphic_entry_point + unchecked_offset",
            "previous_text_offset_",
        )
    if ver < 24 and patch_dump:
        replace_file_text(
            "src/third_party/dart/runtime/vm/clustered_snapshot.cc",
            "monomorphic_entry_point + unchecked_offset",
            "bare_offset",
        )
    if ver < 39 and patch_dump:
        replace_file_text(
            "src/third_party/dart/runtime/vm/app_snapshot.cc",
            "monomorphic_entry_point + unchecked_offset",
            "previous_text_offset_",
        )
    if ver > 38 and patch_dump:
        # NOTE: the monomorphic_unchecked_entry_point_ assignment must stay
        # stock - overwriting that live VM dispatch field with a pc_offset made
        # engines >= 3.44 jump to bogus addresses on unchecked monomorphic
        # calls (issue #385 startup crashes) and produced duplicated offsets.

        # new fix for patch dump
        replace_file_text(
            "src/third_party/dart/runtime/vm/app_snapshot.cc",
            "ASSERT(code->IsCode());",
            'ASSERT(code->IsCode());\n if (WeakSerializationReference::Unwrap(code->untag()->owner()) == static_cast<ObjectPtr>(func.ptr())) { auto& rClass = Class::Handle(func.Owner()); auto& rLib = Library::Handle(rClass.library()); auto& rlibName = String::Handle(rLib.url()); char offsetString[70]; auto const reflutter_entry = reinterpret_cast<uintptr_t>(code->untag()->entry_point_); auto const reflutter_base = reinterpret_cast<uintptr_t>(d->instructions_table().EntryPointAt(0)) - static_cast<uintptr_t>(d->instructions_table().rodata()->entries()[0].pc_offset); snprintf(offsetString, sizeof(offsetString), "0x%016" PRIxPTR, reflutter_entry - reflutter_base); JSONWriter js; js.OpenObject(); js.PrintProperty("method_name", func.UserVisibleNameCString()); js.PrintProperty("offset", offsetString); js.PrintProperty("library_url", rlibName.ToCString()); js.PrintProperty("class_name", rClass.UserVisibleNameCString()); js.CloseObject(); char* buffer = nullptr; intptr_t buffer_length = 0; js.Steal(&buffer, &buffer_length); struct stat entry_info; int exists = 0; if (stat("/data/data/", &entry_info)==0 && S_ISDIR(entry_info.st_mode)){ exists = 1; } if(exists == 1){ pid_t pid = getpid(); char path[64] = { 0 }; snprintf(path, sizeof(path), "/proc/%d/cmdline", pid); FILE *cmdline = fopen(path, "r"); if (cmdline) { char chm[264] = { 0 }; char pat[264] = { 0 }; char application_id[64] = { 0 }; fread(application_id, sizeof(application_id), 1, cmdline); snprintf(pat, sizeof(pat), "/data/data/%s/dump.dart", application_id); do { FILE *f = fopen(pat, "a+"); fprintf(f, "%s", buffer); fflush(f); fclose(f); snprintf(chm, sizeof(chm), "/data/data/%s",application_id); chmod(chm, S_IRWXU|S_IRWXG|S_IRWXO); chmod(pat, S_IRWXU|S_IRWXG|S_IRWXO); } while (0); fclose(cmdline); } } if(exists == 0){ char pat[264] = { 0 }; snprintf(pat, sizeof(pat), "%s/Documents/dump.dart", getenv("HOME")); OS::PrintErr("reFlutter dump file: %s",pat); do { FILE *f = fopen(pat, "a+"); fprintf(f, "%s", buffer); fflush(f); fclose(f); } while (0); } }\n',
        )

    if patch_dump:
        replace_file_text(
            "src/third_party/dart/runtime/vm/dart.cc",
            "FLAG_print_class_table)",
            "true)",
        )
        replace_file_text(
            "src/third_party/dart/runtime/vm/dart_api_impl.cc",
            "FLAG_print_class_table)",
            "true)",
        )
        replace_file_text(
            "src/third_party/dart/runtime/vm/class_table.cc",
            '#include "vm/visitor.h"',
            '#include "vm/visitor.h"\n#include <sys/stat.h>',
        )
        replace_file_text(
            "src/third_party/dart/runtime/vm/app_snapshot.cc",
            '#include "vm/version.h"',
            '#include "vm/version.h"\n#include <sys/stat.h>',
        )

    if ver > 27:
        replace_file_text(
            "src/flutter/BUILD.gn",
            '  if (is_android) {\n    public_deps +=\n        [ "//flutter/shell/platform/android:flutter_shell_native_unittests" ]\n  }',
            "",
        )
        # newer engines list the target inside a deps += [ ... ] block instead
        replace_file_text(
            "src/flutter/BUILD.gn",
            '"//flutter/shell/platform/android:flutter_shell_native_unittests",\n',
            "",
        )

    if 27 < ver < 53 and patch_dump:
        replace_file_text(
            "src/third_party/dart/runtime/vm/class_table.cc",
            "::Print() {",
            '::Print()  { OS::PrintErr("reFlutter");\n char pushArr[1600000]="";\n',
        )
        replace_file_text(
            "src/third_party/dart/runtime/vm/class_table.cc",
            'OS::PrintErr("%" Pd ": %s\\n", i, name.ToCString());',
            '\n     auto& funcs = Array::Handle(cls.functions());    if (funcs.Length()>1000) {    continue;    }	char classText[2500000]=""; 	  String& supname = String::Handle();  	  name = cls.Name();	strcat(classText,cls.ToCString());  	  Class& supcls = Class::Handle();    supcls = cls.SuperClass();  	  if (!supcls.IsNull()) {		 supname = supcls.Name();		  strcat(classText," extends ");		 strcat(classText,supname.ToCString()); 	}		  const auto& interfaces = Array::Handle(cls.interfaces());	auto& interface = Instance::Handle();		  for (intptr_t in = 0;in < interfaces.Length(); in++) {	interface^=interfaces.At(in);	if(in==0){strcat(classText," implements ");} 	  if(in>0){strcat(classText," , ");}		strcat(classText,interface.ToCString());	}		  strcat(classText," {\\n");	const auto& fields = Array::Handle(cls.fields());   	  auto& field = Field::Handle();	auto& fieldType = AbstractType::Handle(); 	  String& fieldTypeName = String::Handle();	String& finame = String::Handle();		  Instance& instance2 = Instance::Handle();		  for (intptr_t f = 0; f < fields.Length(); f++)		  {    field ^= fields.At(f);	finame = field.name();	fieldType = field.type();	fieldTypeName = fieldType.Name();	strcat(classText,"  ");		  strcat(classText,fieldTypeName.ToCString()); 	strcat(classText," ");	strcat(classText,finame.ToCString()); 		  if(field.is_static()){			instance2 ^= field.StaticValue();			strcat(classText," = ");			  strcat(classText,instance2.ToCString());			strcat(classText," ;\\n");  } 	  else {	  strcat(classText," = ");	  strcat(classText," nonstatic;\\n");  }	}  	  for (intptr_t c = 0; c < funcs.Length(); c++) {		    auto& func = Function::Handle();    func = cls.FunctionFromIndex(c);  	  String& signature = String::Handle();    signature = func.InternalSignature();auto& codee = Code::Handle(func.CurrentCode());	  	  if(!func.IsLocalFunction()) {		  strcat(classText," \\n  ");	strcat(classText,func.ToCString());	strcat(classText," ");    strcat(classText,signature.ToCString());		  strcat(classText," { \\n\\n              ");	  char append[70];	  snprintf(append, sizeof(append), " Code Offset: _kDartIsolateSnapshotInstructions + 0x%016" PRIxPTR "\\n",static_cast<uintptr_t>(codee.MonomorphicUncheckedEntryPoint()));	  strcat(classText,append);		  strcat(classText,"       \\n       }\\n");		  } else {		  auto& parf = Function::Handle();	parf=func.parent_function();		  String& signParent = String::Handle();   		  signParent = parf.InternalSignature();			  strcat(classText," \\n  ");			  strcat(classText,parf.ToCString());	strcat(classText," ");	strcat(classText,signParent.ToCString());		  strcat(classText," { \\n\\n          "); 	  char append[80];	  snprintf(append, sizeof(append), " Code Offset: _kDartIsolateSnapshotInstructions + 0x%016" PRIxPTR "\\n",static_cast<uintptr_t>(codee.MonomorphicUncheckedEntryPoint()));	  strcat(classText,append);		  strcat(classText,"       \\n       }\\n");		}	}		  	  strcat(classText," \\n      }\\n\\n");	  	  const Library& libr = Library::Handle(cls.library());if (!libr.IsNull()) {  auto& owner_class = Class::Handle(); owner_class = libr.toplevel_class();   auto& funcsTopLevel = Array::Handle(owner_class.functions());   char pushTmp[1000];   String& owner_name = String::Handle();   owner_name = libr.url();   snprintf(pushTmp, sizeof(pushTmp), "\'%s\',",owner_name.ToCString());  if (funcsTopLevel.Length()>0&&strstr(pushArr, pushTmp) == NULL) {  strcat(pushArr,pushTmp);   strcat(classText,"Library:"); strcat(classText,pushTmp); strcat(classText," {\\n");         for (intptr_t c = 0; c < funcsTopLevel.Length(); c++) {      auto& func = Function::Handle();    func = owner_class.FunctionFromIndex(c);  	  String& signature = String::Handle();    	  signature = func.InternalSignature();	  auto& codee = Code::Handle(func.CurrentCode());	   if(!func.IsLocalFunction()) {		  strcat(classText," \\n  ");	strcat(classText,func.ToCString());	strcat(classText," ");    strcat(classText,signature.ToCString());		  strcat(classText," { \\n\\n              ");	  char append[70];	  snprintf(append, sizeof(append), " Code Offset: _kDartIsolateSnapshotInstructions + 0x%016" PRIxPTR "\\n",static_cast<uintptr_t>(codee.MonomorphicUncheckedEntryPoint()));	  strcat(classText,append);		  strcat(classText,"       \\n       }\\n");		  } else {		  auto& parf = Function::Handle();	parf=func.parent_function();		  String& signParent = String::Handle();   		  signParent = parf.InternalSignature();			  strcat(classText," \\n  ");			  strcat(classText,parf.ToCString());	strcat(classText," ");	strcat(classText,signParent.ToCString());		  strcat(classText," { \\n\\n          "); 	  char append[80];	  snprintf(append, sizeof(append), " Code Offset: _kDartIsolateSnapshotInstructions + 0x%016" PRIxPTR "\\n",static_cast<uintptr_t>(codee.MonomorphicUncheckedEntryPoint()));	  strcat(classText,append);		  strcat(classText,"       \\n       }\\n");		}	  }             strcat(classText," \\n      }\\n\\n");}}	  struct stat entry_info;	  int exists = 0;	  if (stat("/data/data/", &entry_info)==0 && S_ISDIR(entry_info.st_mode)){		  exists=1;	  }	  	  	  if(exists==1){		  pid_t pid = getpid();		  char path[64] = { 0 };		  snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);		  		  FILE *cmdline = fopen(path, "r");		  if (cmdline) {			  	    char chm[264] = { 0 };		char pat[264] = { 0 };        char application_id[64] = { 0 };		        fread(application_id, sizeof(application_id), 1, cmdline);		snprintf(pat, sizeof(pat), "/data/data/%s/dump.dart", application_id);		        do { FILE *f = fopen(pat, "a+");   fprintf(f, "%s",classText);   fflush(f);   fclose(f);   snprintf(chm, sizeof(chm), "/data/data/%s",application_id);  chmod(chm, S_IRWXU|S_IRWXG|S_IRWXO);  chmod(pat, S_IRWXU|S_IRWXG|S_IRWXO);	  } while (0);        fclose(cmdline);    }	  }	  	  	  	  	  	  	  	  	  	  	  	  	  if(exists==0){			  	   		char pat[264] = { 0 };		snprintf(pat, sizeof(pat), "%s/Documents/dump.dart", getenv("HOME"));   OS::PrintErr("reFlutter dump file: %s",pat);     do { FILE *f = fopen(pat, "a+");   fprintf(f, "%s",classText);   fflush(f);   fclose(f);   	  } while (0);         	  }',
        )
    elif ver < 28 and patch_dump:
        replace_file_text(
            "src/third_party/dart/runtime/vm/class_table.cc",
            "::Print() {",
            '::Print()  { OS::PrintErr("reFlutter");\n char pushArr[1600000]="";\n',
        )
        replace_file_text(
            "src/third_party/dart/runtime/vm/class_table.cc",
            'OS::PrintErr("%" Pd ": %s\\n", i, name.ToCString());',
            '\n      auto& funcs = Array::Handle(cls.functions());    if (funcs.Length()>1000) {    continue;    }	char classText[2500000]=""; 	  String& supname = String::Handle();  	  name = cls.Name();	strcat(classText,cls.ToCString());  	  Class& supcls = Class::Handle();    supcls = cls.SuperClass();  	  if (!supcls.IsNull()) {		 supname = supcls.Name();		  strcat(classText," extends ");		 strcat(classText,supname.ToCString()); 	}		  const auto& interfaces = Array::Handle(cls.interfaces());	auto& interface = Instance::Handle();		  for (intptr_t in = 0;in < interfaces.Length(); in++) {	interface^=interfaces.At(in);	if(in==0){strcat(classText," implements ");} 	  if(in>0){strcat(classText," , ");}		strcat(classText,interface.ToCString());	}		  strcat(classText," {\\n");	const auto& fields = Array::Handle(cls.fields());   	  auto& field = Field::Handle();	auto& fieldType = AbstractType::Handle(); 	  String& fieldTypeName = String::Handle();	String& finame = String::Handle();		  Instance& instance2 = Instance::Handle();		  for (intptr_t f = 0; f < fields.Length(); f++)		  {    field ^= fields.At(f);	finame = field.name();	fieldType = field.type();	fieldTypeName = fieldType.Name();	strcat(classText,"  ");		  strcat(classText,fieldTypeName.ToCString()); 	strcat(classText," ");	strcat(classText,finame.ToCString()); 		  if(field.is_static()){			instance2 = field.StaticValue();			strcat(classText," = ");			  strcat(classText,instance2.ToCString());			strcat(classText," ;\\n");  } 	  else {	  strcat(classText," = ");	  strcat(classText," nonstatic;\\n");  }	}  	  for (intptr_t c = 0; c < funcs.Length(); c++) {		    auto& func = Function::Handle();    func = cls.FunctionFromIndex(c);  	  String& signature = String::Handle();    signature = func.Signature();auto& codee = Code::Handle(func.CurrentCode());	  	  if(!func.IsLocalFunction()) {		  strcat(classText," \\n  ");	strcat(classText,func.ToCString());	strcat(classText," ");    strcat(classText,signature.ToCString());		  strcat(classText," { \\n\\n              ");	  char append[70];	  snprintf(append, sizeof(append), " Code Offset: _kDartIsolateSnapshotInstructions + 0x%016" PRIxPTR "\\n",static_cast<uintptr_t>(codee.MonomorphicUncheckedEntryPoint()));	  strcat(classText,append);		  strcat(classText,"       \\n       }\\n");		  } else {		  auto& parf = Function::Handle();	parf=func.parent_function();		  String& signParent = String::Handle();   		  signParent = parf.Signature();			  strcat(classText," \\n  ");			  strcat(classText,parf.ToCString());	strcat(classText," ");	strcat(classText,signParent.ToCString());		  strcat(classText," { \\n\\n          "); 	  char append[80];	  snprintf(append, sizeof(append), " Code Offset: _kDartIsolateSnapshotInstructions + 0x%016" PRIxPTR "\\n",static_cast<uintptr_t>(codee.MonomorphicUncheckedEntryPoint()));	  strcat(classText,append);		  strcat(classText,"       \\n       }\\n");		}	}		  	  strcat(classText," \\n      }\\n\\n");	  	  const Library& libr = Library::Handle(cls.library());if (!libr.IsNull()) {  auto& owner_class = Class::Handle(); owner_class = libr.toplevel_class();   auto& funcsTopLevel = Array::Handle(owner_class.functions());   char pushTmp[1000];   String& owner_name = String::Handle();   owner_name = libr.url();   snprintf(pushTmp, sizeof(pushTmp), "\'%s\',",owner_name.ToCString());  if (funcsTopLevel.Length()>0&&strstr(pushArr, pushTmp) == NULL) {  strcat(pushArr,pushTmp);   strcat(classText,"Library:"); strcat(classText,pushTmp); strcat(classText," {\\n");         for (intptr_t c = 0; c < funcsTopLevel.Length(); c++) {      auto& func = Function::Handle();    func = owner_class.FunctionFromIndex(c);  	  String& signature = String::Handle();    	  signature = func.Signature();	  auto& codee = Code::Handle(func.CurrentCode());	   if(!func.IsLocalFunction()) {		  strcat(classText," \\n  ");	strcat(classText,func.ToCString());	strcat(classText," ");    strcat(classText,signature.ToCString());		  strcat(classText," { \\n\\n              ");	  char append[70];	  snprintf(append, sizeof(append), " Code Offset: _kDartIsolateSnapshotInstructions + 0x%016" PRIxPTR "\\n",static_cast<uintptr_t>(codee.MonomorphicUncheckedEntryPoint()));	  strcat(classText,append);		  strcat(classText,"       \\n       }\\n");		  } else {		  auto& parf = Function::Handle();	parf=func.parent_function();		  String& signParent = String::Handle();   		  signParent = parf.Signature();			  strcat(classText," \\n  ");			  strcat(classText,parf.ToCString());	strcat(classText," ");	strcat(classText,signParent.ToCString());		  strcat(classText," { \\n\\n          "); 	  char append[80];	  snprintf(append, sizeof(append), " Code Offset: _kDartIsolateSnapshotInstructions + 0x%016" PRIxPTR "\\n",static_cast<uintptr_t>(codee.MonomorphicUncheckedEntryPoint()));	  strcat(classText,append);		  strcat(classText,"       \\n       }\\n");		}	  }             strcat(classText," \\n      }\\n\\n");}}	  struct stat entry_info;	  int exists = 0;	  if (stat("/data/data/", &entry_info)==0 && S_ISDIR(entry_info.st_mode)){		  exists=1;	  }	  	  	  if(exists==1){		  pid_t pid = getpid();		  char path[64] = { 0 };		  snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);		  		  FILE *cmdline = fopen(path, "r");		  if (cmdline) {			  	    char chm[264] = { 0 };		char pat[264] = { 0 };        char application_id[64] = { 0 };		        fread(application_id, sizeof(application_id), 1, cmdline);		snprintf(pat, sizeof(pat), "/data/data/%s/dump.dart", application_id);		        do { FILE *f = fopen(pat, "a+");   fprintf(f, "%s",classText);   fflush(f);   fclose(f);   snprintf(chm, sizeof(chm), "/data/data/%s",application_id);  chmod(chm, S_IRWXU|S_IRWXG|S_IRWXO);  chmod(pat, S_IRWXU|S_IRWXG|S_IRWXO);	  } while (0);        fclose(cmdline);    }	  }	  	  	  	  	  	  	  	  	  	  	  	  	  if(exists==0){			  	   		char pat[264] = { 0 };        snprintf(pat, sizeof(pat), "%s/Documents/dump.dart", getenv("HOME"));	OS::PrintErr("reFlutter dump file: %s",pat); 	        do { FILE *f = fopen(pat, "a+");   fprintf(f, "%s",classText);   fflush(f);   fclose(f);   	  } while (0);         	  }',
        )
    replace_file_text(
        "src/third_party/dart/tools/make_version.py",
        "snapshot_hash = MakeSnapshotHashString()",
        "snapshot_hash = '" + libapp_hash + "'",
    )

    replace_file_text(
        "src/third_party/boringssl/src/ssl/ssl_x509.cc",
        "static bool ssl_crypto_x509_session_verify_cert_chain(SSL_SESSION *session,\n                                                      SSL_HANDSHAKE *hs,\n                                                      uint8_t *out_alert) {",
        "static bool ssl_crypto_x509_session_verify_cert_chain(SSL_SESSION *session,\n                                                      SSL_HANDSHAKE *hs,\n                                                      uint8_t *out_alert) {return true;",
    )
    replace_file_text(
        "src/third_party/boringssl/src/ssl/ssl_x509.cc",
        "static int ssl_crypto_x509_session_verify_cert_chain(SSL_SESSION *session,\n                                                      SSL_HANDSHAKE *hs,\n                                                      uint8_t *out_alert) {",
        "static int ssl_crypto_x509_session_verify_cert_chain(SSL_SESSION *session,\n                                                      SSL_HANDSHAKE *hs,\n                                                      uint8_t *out_alert) {return 1;",
    )

    if ver == 26 or ver == 27:
        replace_file_text(
            "tools/generate_package_config/pubspec.yaml",
            "package_config: any",
            "package_config: 1.9.3",
        )
    if ver == 24:
        replace_file_text(
            "DEPS",
            "flutter_internal/android/sdk/licenses",
            "flutter/android/sdk/licenses",
        )
    if ver == 14 or ver == 13:
        replace_file_text(
            "DEPS",
            "   'src/third_party/dart/pkg/analysis_server/language_model': {\n     'packages': [\n       {\n        'package': 'dart/language_model',\n        'version': 'lIRt14qoA1Cocb8j3yw_Fx5cfYou2ddam6ArBm4AI6QC',\n       }\n     ],\n     'dep_type': 'cipd',\n   },\n",
            "",
        )
    if 13 >= ver > 10:
        replace_file_text(
            "DEPS",
            "  'src/third_party/tonic':\n   Var('fuchsia_git') + '/tonic' + '@' + '1a8ed9be2e2b56b32e888266d6db465d36012df4',\n",
            "",
        )
        try:
            shutil.copytree("../tonic", "src/third_party/tonic")
        except Exception:
            pass
    if 10 >= ver > 6:
        replace_file_text(
            "DEPS",
            "  'src/third_party/tonic':\n   Var('fuchsia_git') + '/tonic' + '@' + 'bd27b4549199df72fcaeefd259ebc12a31c2e4ee',\n",
            "",
        )
        try:
            shutil.copytree("../tonic", "src/third_party/tonic")
        except Exception:
            pass
    if ver == 11 or ver == 10 or ver == 9 or ver == 8:
        replace_file_text(
            "DEPS",
            "   'src/third_party/dart/tools/sdks': {\n     'packages': [\n       {\n         'package': 'dart/dart-sdk/${{platform}}',\n         'version': 'version:2.4.0'\n       }\n     ],\n     'dep_type': 'cipd',\n   },\n",
            "",
        )
        replace_file_text(
            "DEPS",
            "   'src/third_party/dart/pkg/analysis_server/language_model': {\n     'packages': [\n       {\n        'package': 'dart/language_model',\n        'version': '9fJQZ0TrnAGQKrEtuL3-AXbUfPzYxqpN_OBHr9P4hE4C',\n       }\n     ],\n     'dep_type': 'cipd',\n   },\n",
            "",
        )
        replace_file_text(
            "DEPS",
            "   'src/third_party/dart/pkg/analysis_server/language_model': {\n     'packages': [\n       {\n        'package': 'dart/language_model',\n        'version': 'EFtZ0Z5T822s4EUOOaWeiXUppRGKp5d9Z6jomJIeQYcC',\n       }\n     ],\n     'dep_type': 'cipd',\n   },\n",
            "",
        )
        replace_file_text(
            "DEPS",
            "   'src/third_party/dart/pkg/analysis_server/language_model': {\n     'packages': [\n       {\n        'package': 'dart/language_model',\n        'version': 'gABkW8D_-f45it57vQ_ZTKFwev16RcCjvrdTCytEnQgC',\n       }\n     ],\n     'dep_type': 'cipd',\n   },\n",
            "",
        )
