[![stars](https://img.shields.io/github/stars/Impact-I/reFlutter)](https://github.com/Impact-I/reFlutter/stargazers)

<p align="center"><img src="https://user-images.githubusercontent.com/87244850/135659542-22bb8496-bf26-4e25-b7c1-ffd8fc0cea10.png" width="75%"/></p>

**Read more on the blog:** <https://swarm.ptsecurity.com/fork-bomb-for-flutter/>

This framework helps with Flutter apps reverse engineering using the patched version of the Flutter library which is already compiled and ready for app repacking. This library has snapshot deserialization process modified to allow you perform dynamic analysis in a convenient way.

Key features:

- `socket.cc` is patched for traffic monitoring and interception;
- `dart.cc` is modified to print classes, functions and some fields;
- dump mode emits `dump.dart` with class/library/function names and per-function code offsets (ready to use with `frida.js`);
- contains minor changes for successful compilation;
- if you would like to implement your own patches, manual Flutter code changes are supported using a specially crafted `Dockerfile`.

### Supported engines

- Android: arm64, arm32, x64;
- iOS: arm64;
- Release: Stable, Beta — engine coverage is keyed by snapshot hash, see [enginehash.csv](https://github.com/Impact-I/reFlutter/blob/main/enginehash.csv)

### Install

```
# Linux, Windows, MacOS
pip3 install reflutter==0.9.1
```

### Usage

```console
impact@f:~$ reflutter main.apk

Please enter your Burp Suite IP: <input_ip>

SnapshotHash: 8ee4ef7a67df9845fba331734198a953
The resulting apk file: ./release.RE.apk
Please sign the apk file

impact@f:~$ reflutter main.ipa
```

Options:

- `-p, --patch-dump` — dump mode: patch the engine to emit `dump.dart` (classes/methods/offsets) on start, and print a `frida.js` hint instead of the proxy instructions.
- `-n, --no-interact` — never prompt for a Burp IP (implies `127.0.0.1`); useful for old engines in CI.
- `-b <Snapshot_Hash>, --build-engine` — engine build mode: print the engine commit for a snapshot hash and (when run inside a flutter/flutter checkout) apply the reFlutter source patches. See `scripts/local-release`.

### Traffic interception

You need to specify the IP of your Burp Suite Proxy Server located in the same network where the device with the Flutter application is. Then configure the Proxy in `BurpSuite -> Listener Proxy -> Options tab`:

- Add port: `8083`
- Bind to address: `All interfaces`
- Request handling: Support invisible proxying = `True`

<p align="center"><img src="https://user-images.githubusercontent.com/87244850/135753172-20489ef9-0759-432f-b2fa-220607e896b8.png" width="84%"/></p>

No certificate installation or root access is required for Android. reFlutter also allows bypassing some of the Flutter certificate pinning implementations.

> ⚠️ **Note:** Engines up to and including Flutter **3.24.x** (snapshot hash `80a49c7111088100a233b2ae788e1f48`) still carry the hardcoded proxy IP and get patched in place. Starting with **3.27.x** the hardcoded IP is gone — configure the proxy directly on the device instead.

#### On Android

Use ADB to configure the device’s proxy:

```bash
adb -s <device> shell "settings put global http_proxy <proxy_ip:port>"
```

Sign, align, and install the APK. Optionally configure **TunProxy** to route traffic through Burp Suite.

#### On iOS

Sign and install the IPA. Configure **Potatso** to use your Burp Suite proxy server.

### Usage on Android

The resulting apk must be aligned and signed. A recommended tool is [uber-apk-signer](https://github.com/patrickfav/uber-apk-signer/releases/tag/v1.2.1):

```bash
java -jar uber-apk-signer.jar --allowResign -a release.RE.apk
```

Run the app on a device. Determine `_kDartIsolateSnapshotInstructions` via binary search. reFlutter writes the dump file to the app's root folder and sets 777 permissions. Retrieve it using:

```bash
adb -d shell "cat /data/data/<PACKAGE_NAME>/dump.dart" > dump.dart
```

<details>
<summary>file contents</summary>

```dart
Library:'package:anyapp/navigation/DeepLinkImpl.dart' Class: Navigation extends Object {
String* DeepUrl = anyapp://evil.com/ ;
...
```

</details>

### Usage on iOS

After running `reflutter main.ipa`, execute the app on device. The dump file path is printed to Xcode console logs:

```
Current working dir: /private/var/mobile/Containers/Data/Application/<UUID>/dump.dart
```

Retrieve the file from the device.

<p align="center"><img src="https://user-images.githubusercontent.com/87244850/135860648-a13ba3fd-93d2-4eab-bd38-9aa775c3178f.png" width="100%"/></p>

### Frida

```
frida-tools==13.7.1
frida==16.7.19
```

Use dump offsets in the Frida [script](https://github.com/Impact-I/reFlutter/blob/main/frida.js). The script resolves the snapshot-instructions symbol automatically — it is exported as `_kDartSnapshotText` in newer Dart and `_kDartIsolateSnapshotInstructions` in older versions — and works across Frida 14–17. Recent frida-server versions are recommended (16.x servers predate Android 15+ and cannot inject there):

```bash
frida -U -f <package> -l frida.js
```

For traffic interception **without repacking at all** - on stock,
custom, CI, or debug engines - use the runtime SSL bypass:

```bash
frida -U -f <package> -l frida-ssl.js
```

It locates boringssl's certificate-chain verification inside the loaded
libflutter.so (exported symbol first, then a byte-signature scan for
stripped builds) and patches it to accept any chain - route the device
through your proxy and you are intercepting.

### Shorebird builds

Apps built with [Shorebird](https://shorebird.dev) use a patched Flutter engine whose snapshot hash differs from the vanilla Flutter release it is based on. reFlutter identifies these automatically (a hash found only in [enginehash_sb.csv](https://github.com/Impact-I/reFlutter/blob/main/enginehash_sb.csv) identifies a Shorebird app even when `flutter_assets/shorebird.yaml` is absent) and patches them for **traffic interception** with no engine build: Shorebird's own engine artifact is fetched from their public bucket for the matched revision, boringssl's certificate-chain verification is patched to succeed unconditionally (a pure-Python ELF walk — symbol table to file offset to an 8-byte arm64 patch — after which the ~150MB of shipped symbols are dropped, since Android's linker only reads program headers), and the app is repacked with it. Refresh the hash list any time with:

```bash
python3 scripts/gen_enginehash.py --shorebird
```

Notes: our own engines cannot run Shorebird snapshots (their code lives in patchable regions understood only by their private Dart fork's loader — verified empirically), which is exactly why the binary-patch route is used. Android arm64/arm32/x64 are patched per-ABI. iOS frameworks are Mach-O patched using the dSYM of the same build for exact symbol addresses (shipped frameworks are stripped) — the resulting ipa must be re-signed, as the tool's output already instructs. Dump mode for Shorebird engines remains blocked on the private Dart fork.

### Profile and Debug builds

Apps built with `flutter build --profile` carry the same snapshot hash as
their release counterparts (verified across engines: the hash covers the VM
sources, not the runtime mode, and profile/release AOT snapshots are
format-compatible) - so profile-mode apps work with the regular release
engine assets already. `scripts/gen_enginehash.py --profile` re-verifies
this for new engines.

Debug builds are genuinely different (JIT kernel snapshots, no AOT
libapp.so, and the debug libflutter artifact embeds its engine commit
rather than a snapshot hash) - but they no longer need an engine build
for traffic analysis: `frida-ssl.js` (runtime SSL bypass, below) works
on stock engines of any runtime mode, including debug.

### To Do

- [x] Display absolute code offset for functions;
- [x] Extract more strings and fields (is_static, parameter_count in the
      JSONL dump; frida.js auto-written next to -p output);
- [x] Add socket patch;
- [ ] Extend engine support to Debug using Fork and Github Actions;
- [x] Improve detection of `App.framework` and `libapp.so` inside zip archive (fallback scan + x86 path fixed in 0.9.0)

### Build Engine

Engines are built with `scripts/local-release` (macOS; builds v2 + v3 for iOS and Android arm64/arm/x64, verifies every patch landed, and uploads the release assets) based on data in [enginehash.csv](https://github.com/Impact-I/reFlutter/blob/main/enginehash.csv). The engine commit for a snapshot hash is resolved via `reflutter -b <Snapshot_Hash>`. Snapshot hash is retrieved from:

```
https://storage.googleapis.com/flutter_infra_release/flutter/<hash>/android-arm64-release/linux-x64.zip
```

<details>
<summary>release</summary>

[![gif](https://user-images.githubusercontent.com/87244850/135758767-47b7d51f-8b6c-40b5-85aa-a13c5a94423a.gif)](https://github.com/Impact-I/reFlutter/actions)

</details>

### Custom Build

Manual Flutter code patching is supported using Docker:

```bash
git clone https://github.com/Impact-I/reFlutter && cd reFlutter
docker build -t reflutter -f Dockerfile .
```

Run with:

```bash
docker run -it -v "$(pwd):/t" -e HASH_PATCH=<Snapshot_Hash> -e COMMIT=<Engine_commit> reflutter
```

Example:

```bash
docker run -it -v "$(pwd):/t" -e HASH_PATCH=aa64af18e7d086041ac127cc4bc50c5e -e COMMIT=d44b5a94c976fbb65815374f61ab5392a220b084 reflutter
```

#### Example: Build Android ARM64 (Linux/Windows)

```bash
docker run -e WAIT=300 -e x64=0 -e arm=0 -e HASH_PATCH=<Snapshot_Hash> -e COMMIT=<Engine_commit> --rm -iv${PWD}:/t reflutter
```

Flags:

- `-e x64=0`: disables x64 build
- `-e arm64=0`: disables arm64 build
- `-e arm=0`: disables arm32 build
- `-e WAIT=300`: time in seconds to modify source before build
- `-e HASH_PATCH`: snapshot hash from `enginehash.csv`
- `-e COMMIT`: engine commit hash

---
