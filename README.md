[![stars](https://img.shields.io/github/stars/Impact-I/reFlutter)](https://github.com/Impact-I/reFlutter/stargazers)

<p align="center"><img src="https://user-images.githubusercontent.com/87244850/135659542-22bb8496-bf26-4e25-b7c1-ffd8fc0cea10.png" width="75%"/></p>

**Read more on the blog:** <https://swarm.ptsecurity.com/fork-bomb-for-flutter/>

This framework helps with Flutter apps reverse engineering using the patched version of the Flutter library which is already compiled and ready for app repacking. This library has snapshot deserialization process modified to allow you perform dynamic analysis in a convenient way.

Key features:

- `socket.cc` is patched for traffic monitoring and interception;
- `dart.cc` is modified to print classes, functions and some fields;
- display absolute code offset for functions;
- contains minor changes for successful compilation;
- if you would like to implement your own patches, manual Flutter code changes are supported using a specially crafted `Dockerfile`.

### Supported engines

- Android: arm64, arm32;
- iOS: arm64;
- Release: Stable, Beta

### Install

```
# Linux, Windows, MacOS
pip3 install reflutter==0.8.5
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

### Traffic interception

You need to specify the IP of your Burp Suite Proxy Server located in the same network where the device with the Flutter application is. Then configure the Proxy in `BurpSuite -> Listener Proxy -> Options tab`:

- Add port: `8083`
- Bind to address: `All interfaces`
- Request handling: Support invisible proxying = `True`

<p align="center"><img src="https://user-images.githubusercontent.com/87244850/135753172-20489ef9-0759-432f-b2fa-220607e896b8.png" width="84%"/></p>

No certificate installation or root access is required for Android. reFlutter also allows bypassing some of the Flutter certificate pinning implementations.

> ⚠️ **Note:** Starting from Flutter version **3.24.0** (snapshot hash: `80a49c7111088100a233b2ae788e1f48`), the hardcoded proxy IP and port have been removed. You now need to configure your proxy directly on the device.

#### On Android:

Use ADB to configure the device’s proxy:

```bash
adb -s <device> shell "settings put global http_proxy <proxy_ip:port>"
```

Sign, align, and install the APK. Optionally configure **TunProxy** to route traffic through Burp Suite.

#### On iOS:

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

Use dump offsets in the Frida [script](https://github.com/Impact-I/reFlutter/blob/main/frida.js):

```bash
frida -U -f <package> -l frida.js
```

To find `_kDartIsolateSnapshotInstructions`:

```bash
readelf -Ws libapp.so
```

Look for the `Value` field.

### To Do

- [x] Display absolute code offset for functions;
- [ ] Extract more strings and fields;
- [x] Add socket patch;
- [ ] Extend engine support to Debug using Fork and Github Actions;
- [ ] Improve detection of `App.framework` and `libapp.so` inside zip archive

### Build Engine

Engines are built using [GitHub Actions](https://github.com/Impact-I/reFlutter/actions) based on data in [enginehash.csv](https://github.com/Impact-I/reFlutter/blob/main/enginehash.csv). Snapshot hash is retrieved from:

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
