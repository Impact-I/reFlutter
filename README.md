[![stars](https://img.shields.io/github/stars/Impact-I/reFlutter)](https://github.com/Impact-I/reFlutter/stargazers)

<p align="center"><img src="https://user-images.githubusercontent.com/87244850/135659542-22bb8496-bf26-4e25-b7c1-ffd8fc0cea10.png" width="75%"/></p>

**Read more on the blog:** https://swarm.ptsecurity.com/fork-bomb-for-flutter/

This framework helps with Flutter apps reverse engineering using the patched version of the Flutter library which is already compiled and ready for app repacking. This library has snapshot deserialization process modified to allow you perform dynamic analysis in a convenient way.

Key features:

- `socket.cc` is patched for traffic monitoring and interception;
- `dart.cc` is modified to print classes, functions and some fields;
- display absolute code offset for functions
- contains minor changes for successfull compilation;
- if you would like to implement your own patches, there is manual Flutter code change is supported using specially crafted `Dockerfile`

### Supported engines

- Android: arm64, arm32;
- iOS: arm64;
- Release: Stable, Beta

### Install

```
# Linux, Windows, MacOS
pip3 install reflutter==0.7.8
```

### Usage

```console
impact@f:~$ reflutter main.apk

Please enter your Burp Suite IP: <input_ip>

SnapshotHash: 8ee4ef7a67df9845fba331734198a953
The resulting apk file: ./release.RE.apk
Please sign the apk file

Configure Burp Suite proxy server to listen on *:8083
Proxy Tab -> Options -> Proxy Listeners -> Edit -> Binding Tab

Then enable invisible proxying in Request Handling Tab
Support Invisible Proxying -> true

impact@f:~$ reflutter main.ipa
```

### Traffic interception

You need to specify the IP of your Burp Suite Proxy Server located in the same network where the device with the flutter application is. Next, you should configure the Proxy in `BurpSuite -> Listener Proxy -> Options tab`

- Add port: `8083`
- Bind to address: `All interfaces`
- Request handling: Support invisible proxying = `True`
<p align="center"><img src="https://user-images.githubusercontent.com/87244850/135753172-20489ef9-0759-432f-b2fa-220607e896b8.png" width="84%"/></p>

You don't need to install any certificates. On an Android device, you don't need root access as well. reFlutter also allows to bypass some of the flutter certificate pinning implementations.

### Usage on Android

The resulting apk must be aligned and signed. I use [uber-apk-signer](https://github.com/patrickfav/uber-apk-signer/releases/tag/v1.2.1)
`java -jar uber-apk-signer.jar --allowResign -a release.RE.apk`.
To see which code is loaded through DartVM, you need to run the application on the device. Note that you must manually find what `_kDartIsolateSnapshotInstructions` (ex. 0xB000 ) equals to using a binary search. reFlutter writes the dump to the root folder of the application and sets `777` permissions to the file and folder. You can pull the file with adb command

```console
impact@f:~$ adb -d shell "cat /data/data/<PACKAGE_NAME>/dump.dart" > dump.dart
```

<details>
<summary>file contents</summary>

```dart
Library:'package:anyapp/navigation/DeepLinkImpl.dart' Class: Navigation extends Object {
String* DeepUrl = anyapp://evil.com/ ;
 Function 'Navigation.': constructor. (dynamic, dynamic, dynamic, dynamic) => NavigationInteractor {

              Code Offset: _kDartIsolateSnapshotInstructions + 0x0000000000009270

                   }

 Function 'initDeepLinkHandle':. (dynamic) => Future<void>* {

              Code Offset: _kDartIsolateSnapshotInstructions + 0x0000000000412fe8

                   }

 Function '_navigateDeepLink@547106886':. (dynamic, dynamic, {dynamic navigator}) => void {

              Code Offset: _kDartIsolateSnapshotInstructions + 0x0000000000002638

                   }

       }

Library:'package:anyapp/auth/navigation/AuthAccount.dart' Class: AuthAccount extends Account {
PlainNotificationToken* _instance = sentinel;

 Function 'getAuthToken':. (dynamic, dynamic, dynamic, dynamic) => Future<AccessToken*>* {

               Code Offset: _kDartIsolateSnapshotInstructions + 0x00000000003ee548

                   }

 Function 'checkEmail':. (dynamic, dynamic) => Future<bool*>* {

               Code Offset: _kDartIsolateSnapshotInstructions + 0x0000000000448a08

                   }
 Function 'validateRestoreCode':. (dynamic, dynamic, dynamic) => Future<bool*>* {

               Code Offset: _kDartIsolateSnapshotInstructions + 0x0000000000412c34

                   }
 Function 'sendSmsRestorePassword':. (dynamic, dynamic) => Future<bool*>* {

               Code Offset: _kDartIsolateSnapshotInstructions + 0x00000000003efb88

                   }
       }
```

</details>

### Usage on iOS

Use the IPA file created after the execution of `reflutter main.ipa` command. To see which code is loaded through DartVM, you need to run the application on the device. reFlutter will print the dump file path to the Xcode console logs with the reFlutter tag
`Current working dir: /private/var/mobile/Containers/Data/Application/<UUID>/dump.dart`
Next, you will need to pull the file from the device

<p align="center"><img src="https://user-images.githubusercontent.com/87244850/135860648-a13ba3fd-93d2-4eab-bd38-9aa775c3178f.png" width="100%"/></p>

### Frida

The resulting offset from the dump can be used in the frida [script](https://github.com/Impact-I/reFlutter/blob/main/frida.js)

```
frida -U -f <package> -l frida.js --no-pause
```

To get value for `_kDartIsolateSnapshotInstructions` you can use `readelf -Ws libapp.so` Where is the value you need in the `Value` field

### To Do

- [x] Display absolute code offset for functions;
- [ ] Extract more strings and fields;
- [x] Add socket patch;
- [ ] Extend engine support to Debug using Fork and Github Actions;
- [ ] Improve detection of `App.framework` and `libapp.so` inside zip archive

### Build Engine

The engines are built using [reFlutter](https://github.com/Impact-I/reFlutter/blob/main/.github/workflows/main.yml) in [Github Actions](https://github.com/Impact-I/reFlutter/actions) to build the desired version, commits and snapshot hashes are used from this [table](https://github.com/Impact-I/reFlutter/blob/main/enginehash.csv).
The hash of the snapshot is extracted from `storage.googleapis.com/flutter_infra_release/flutter/<hash>/android-arm64-release/linux-x64.zip`

<details>
<summary>release</summary>
  
[![gif](https://user-images.githubusercontent.com/87244850/135758767-47b7d51f-8b6c-40b5-85aa-a13c5a94423a.gif)](https://github.com/Impact-I/reFlutter/actions)
  
</details>

### Custom Build

If you would like to implement your own patches, manual Flutter code change is supported using specially crafted [Docker](https://hub.docker.com/r/ptswarm/reflutter)

```bash
git clone https://github.com/Impact-I/reFlutter && cd reFlutter
docker build -t reflutter -f Dockerfile .
```

Build command:

```bash
docker run -it -v "$(pwd):/t" -e HASH_PATCH=<Snapshot_Hash> -e COMMIT=<Engine_commit> reflutter
```

Example:

```bash
docker run -it -v "$(pwd):/t" -e HASH_PATCH=aa64af18e7d086041ac127cc4bc50c5e -e COMMIT=d44b5a94c976fbb65815374f61ab5392a220b084 reflutter
```

# Linux, Windows

EXAMPLE BUILD ANDROID ARM64:
docker run -e WAIT=300 -e x64=0 -e arm=0 -e HASH_PATCH=<Snapshot_Hash> -e COMMIT=<Engine_commit> --rm -iv${PWD}:/t reflutter

FLAGS:
-e x64=0 <disables building for x64 architecture, use to reduce building time>
-e arm64=0 <disables building for arm64 architecture, use to reduce building time>
-e arm=0 <disables building for arm32 architecture, use to reduce building time>
-e WAIT=300 <the amount of time in seconds you need to edit source code>
-e HASH_PATCH=[Snapshot_Hash] <here you need to specify snapshot hash which matches the engine_commit line of enginehash.csv table best. It is used for proper patch search in reFlutter and for successfull compilation>
-e COMMIT=[Engine_commit] <here you specify commit for your engine version, take it from enginehash.csv table or from flutter/engine repo>
