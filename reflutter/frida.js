// frida -U -f <package> -l frida.js
//
// Offsets come from dump.dart (JSONL), one per line:
//   {"method_name":"...","offset":"0x...","library_url":"...","class_name":"..."}
// The offset is relative to the Dart instructions image start
// (_kDartIsolateSnapshotInstructions) inside libapp.so (Android) or
// App.framework/App (iOS) - NOT to the module base.
//
// Works across Frida 14 - 17: uses only APIs present in all versions
// (Process.findModuleByName, NativePointer.readByteArray) with guarded
// fallbacks for the legacy Module statics removed in newer releases.

var DUMP_OFFSET = "0x20801C"; // <- replace with an offset from dump.dart

var HOOK_LABEL = "hooked";

function candidateModules() {
  // Android: libapp.so. iOS: the Dart AOT snapshot lives in
  // App.framework/App (module "App") or FlutterApp.framework (older builds).
  if (Process.platform === "darwin") {
    return ["App", "FlutterApp", "libapp.so"];
  }
  return ["libapp.so"];
}

function resolveImageBase() {
  // Preferred: the exported snapshot-instructions symbol. gen_snapshot ELFs
  // export it in the dynamic symbol table (the engine dlsym()s it), but the
  // name changed across Dart versions - try both.
  var symbolNames = ["_kDartSnapshotText", "_kDartIsolateSnapshotInstructions"];
  for (var i = 0; i < candidateModules().length; i++) {
    var name = candidateModules()[i];
    var mod = Process.findModuleByName(name);
    if (mod === null) {
      continue;
    }
    var sym = null;
    var viaSymbol = false;
    // enumerateExports() is an instance method that has existed since early
    // Frida and is the only lookup that reliably finds the snapshot symbols
    // on Android (linker namespaced, exported as variables - the global
    // lookups miss them and Module.findExportByName is gone in Frida 17).
    try {
      mod.enumerateExports().forEach(function (e) {
        if (sym !== null) return;
        for (var s = 0; s < symbolNames.length; s++) {
          if (e.name === symbolNames[s]) {
            sym = e.address;
            viaSymbol = true;
          }
        }
      });
    } catch (e) {
      /* module still loading */
    }
    for (var s = 0; s < symbolNames.length && (sym === null || sym.isNull()); s++) {
      try {
        sym = Module.findExportByName(name, symbolNames[s]);
      } catch (e) {
        /* removed in Frida 17 */
      }
      if (sym === null || sym.isNull()) {
        try {
          sym = Module.getGlobalExportByName(symbolNames[s]);
        } catch (e) {
          /* not available in older Frida */
        }
      }
      if (sym !== null && !sym.isNull()) {
        viaSymbol = true;
        break;
      }
    }
    if (viaSymbol) {
      return { base: sym, module: name, viaSymbol: true };
    }
    // Legacy fallback: old dumps used module-relative offsets - keep the
    // module base for those and say so explicitly.
    return { base: mod.base, module: name, viaSymbol: false };
  }
  return null;
}

function isReadable(address) {
  if (address === null || address === undefined) return false;
  try {
    if (address.isNull()) return false;
    // raw integers (Dart returns ints, not pointers) make readByteArray throw
    if (address.compare(0x10000) < 0) return false;
    address.readByteArray(1);
    return true;
  } catch (e) {
    return false;
  }
}

function dumpArgs(step, address, bufSize) {
  if (!isReadable(address)) {
    console.log(
      "Argument " + step + ": " + address + " (not a readable pointer, skipping hexdump)"
    );
    return;
  }
  var buf;
  try {
    buf = address.readByteArray(bufSize); // NativePointer method: Frida 14+
  } catch (e) {
    console.log("Argument " + step + ": unreadable (" + e + ")");
    return;
  }
  console.log(
    "Argument " +
      step +
      " address " +
      address.toString() +
      " buffer: " +
      bufSize +
      "\n\n Value:\n" +
      hexdump(buf, { offset: 0, length: bufSize, header: false, ansi: false })
  );
  console.log("\n----------------------------------------------------\n");
}

function hookFunc() {
  var resolved = resolveImageBase();
  if (resolved === null) {
    return false; // module not loaded yet (spawn race) - caller retries
  }

  console.log(
    "module: " +
      resolved.module +
      " | image base: " +
      resolved.base.toString() +
      " (" +
      (resolved.viaSymbol
        ? "_kDartIsolateSnapshotInstructions"
        : "module base - legacy offsets only") +
      ")"
  );

  var codeOffset = resolved.base.add(DUMP_OFFSET);
  console.log("hooking " + DUMP_OFFSET + " -> " + codeOffset.toString() + "\n");

  Interceptor.attach(codeOffset, {
    onEnter: function (args) {
      console.log("--------------------------------------------|");
      console.log(" Hook: " + DUMP_OFFSET + " (" + HOOK_LABEL + ")");
      console.log("--------------------------------------------|");
      for (var argStep = 0; argStep < 10; argStep++) {
        try {
          dumpArgs(argStep, args[argStep], 150);
        } catch (e) {
          break;
        }
      }
    },
    onLeave: function (retval) {
      console.log("RETURN : " + retval);
      dumpArgs(0, retval, 150);
    },
  });
  return true;
}

// With `frida -f` the app is spawned suspended and libapp.so may not be
// mapped yet at script start - retry until it appears instead of bailing.
var attempts = 0;
var timer = setInterval(function () {
  attempts++;
  if (hookFunc()) {
    clearInterval(timer);
    console.log("[*] hook installed after " + attempts + " attempt(s)");
  } else if (attempts >= 30) {
    clearInterval(timer);
    console.log(
      "ERROR: Dart snapshot module not found after " + attempts + "s - is this a release Flutter app?"
    );
  }
}, 1000);
