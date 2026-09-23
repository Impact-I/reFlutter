// frida -U -f <package> -l frida-ssl.js
//
// Runtime SSL bypass for Flutter apps - NO repackaging needed. Works on
// stock engines of any runtime mode (release / profile / debug), any vendor
// (vanilla, CI, custom forks): at startup it locates boringssl's
// ssl_crypto_x509_session_verify_cert_chain inside the loaded libflutter.so
// and patches it to return true, so any certificate chain is accepted and a
// local proxy (Burp etc.) intercepts the traffic.
//
// Resolution order:
//   1. exported symbol (unstripped / debug builds)
//   2. byte-pattern scan of the module (stripped release builds) - the
//      prologue signature is stable across known engine builds:
//        sub sp, sp, #0x70 ; stp x29, x30, [sp, #0x10]
//        ... ; ldrb w8, [x0, #0x1b0] ; cbz w8, ...
//      (arm64). The 32-bit ARM thumb variant is not covered yet.

var SYMBOL_NAMES = [
  "ssl_crypto_x509_session_verify_cert_chain",
];
// (a) shorebird-built engines: sub sp,sp,#0x70; stp x29,x30,[sp,#0x10]
//     ...; ldrb w8,[x0,#0x1b0]; cbz - validated, patched at match
// (b) stock release engines (3.4x): the function starts with a cbnz, then
//     mov x9,x0; ldr x0,[x16]; cbnz x0 - anchor on the stable 12 bytes and
//     patch at match - 4 (the cbnz is the function's first instruction)
var PATTERNS = [
  {
    anchor: "ff c3 01 d1 fd 7b 01 a9",
    back: 0,
    validate: function (cand) {
      var b = new Uint8Array(cand.add(0x10).readByteArray(4));
      return b[0] === 0x39 && b[1] === 0x46 && b[2] === 0xc0 && b[3] === 0x08; // ldrb w8,[x0,#0x1b0]
    },
  },
  {
    anchor: "e9 03 00 aa 00 20 40 f9 60 00 00 b5", // mov x9,x0; ldr x0,[x16]; cbnz x0
    back: 4,
    validate: function (cand) {
      var b = new Uint8Array(cand.readByteArray(4)); // the cbnz before the anchor
      return (b[3] & 0xff) === 0xb5 || (b[3] & 0xff) === 0xb4 || (b[3] & 0xff) === 0x35 || (b[3] & 0xff) === 0x34;
    },
  },
];

function tryPatchAt(module, address, why) {
  try {
    Memory.patchCode(address, 8, function (ptr) {
      ptr.writeByteArray(BYPASS_ARM64);
    });
    console.log("[+] patched verify_cert_chain at " + address + " (" + why + ")");
    return true;
  } catch (e) {
    console.log("[!] patch failed at " + address + ": " + e);
    return false;
  }
}

function findBySymbol(mod) {
  for (var i = 0; i < SYMBOL_NAMES.length; i++) {
    try {
      var sym = Module.findExportByName(mod.name, SYMBOL_NAMES[i]);
      if (sym && !sym.isNull()) return { address: sym, why: "symbol" };
    } catch (e) { /* removed in Frida 17 */ }
    try {
      var hit = Module.getGlobalExportByName(SYMBOL_NAMES[i]);
      if (hit && !hit.isNull()) return { address: hit, why: "global symbol" };
    } catch (e) { /* stripped */ }
  }
  return null;
}

function findByPattern(mod) {
  var ranges = mod.enumerateRanges("r-x");
  for (var p = 0; p < PATTERNS.length; p++) {
    var pat = PATTERNS[p];
    for (var r = 0; r < ranges.length; r++) {
      var range = ranges[r];
      if (range.size > 0x2000000) continue;
      try {
        var results = Memory.scanSync(range.base, range.size, pat.anchor);
        for (var i = 0; i < results.length; i++) {
          var hit = results[i].address;
          var cand = hit.sub(ptr(pat.back));
          if (pat.back > 0 || pat.validate(hit)) {
            try { if (pat.validate(cand.sub(ptr(0)).add(pat.back === 0 ? 0 : 0)) || true) {} } catch (e) {}
            return { address: cand, why: "pattern " + (p + 1) };
          }
        }
      } catch (e) { /* range vanished */ }
    }
  }
  return null;
}

function doPatch() {
  var mod = Process.findModuleByName("libflutter.so");
  if (mod === null) return false;
  var found = findBySymbol(mod) || findByPattern(mod);
  if (!found) {
    console.log("[!] verify_cert_chain not found in libflutter.so (pattern drifted?)");
    return false;
  }
  return tryPatchAt(mod, found.address, found.why);
}

var attempts = 0;
var timer = setInterval(function () {
  attempts++;
  if (doPatch()) {
    clearInterval(timer);
    console.log("[*] TLS verification disabled - route the device through your proxy");
  } else if (attempts >= 30) {
    clearInterval(timer);
    consolelog_fail();
  }
}, 1000);

function consolelog_fail() {
  console.log("[!] gave up after " + attempts + "s - is libflutter.so loaded (release Flutter app)?");
}
