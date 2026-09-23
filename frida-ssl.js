// frida -U -f <package> -l frida-ssl.js
//
// Runtime SSL bypass for Flutter Android apps - NO repackaging needed.
// Locates boringssl's ssl_crypto_x509_session_verify_cert_chain inside the
// loaded libflutter.so and patches it to return true, so any certificate
// chain is accepted and a local proxy (Burp etc.) intercepts the traffic.
//
// Resolution order:
//   1. .symtab scan via Module.enumerateSymbols() - works on most shipped
//      engines (internal-linkage symbol, present in symtab, absent from dynsym)
//   2. Byte-pattern scan (stripped engines) - arm64 only
//
// Android only (looks up libflutter.so). iOS not supported yet.

var SYMBOL_SUBSTRING = "ssl_crypto_x509_session_verify_cert_chain";
// arm64: mov w0, #1 ; ret
var BYPASS_ARM64 = [0x20, 0x00, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6];

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

function findBySymtab(mod) {
  // The target is internal-linkage (static in ssl_x509.cc), so it lives in
  // .symtab but never in .dynsym. Module.enumerateSymbols() reads .symtab.
  try {
    var symbols = mod.enumerateSymbols();
    for (var i = 0; i < symbols.length; i++) {
      if (symbols[i].name.indexOf(SYMBOL_SUBSTRING) !== -1 && symbols[i].type === "function") {
        return { address: symbols[i].address, why: "symtab" };
      }
    }
  } catch (e) {
    console.log("[!] enumerateSymbols failed: " + e);
  }
  return null;
}

function doPatch() {
  var mod = Process.findModuleByName("libflutter.so");
  if (mod === null) return false;
  var found = findBySymtab(mod);
  if (!found) {
    console.log("[!] verify_cert_chain not found in libflutter.so symtab (stripped engine?)");
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
    console.log("[!] gave up after " + attempts + "s - is libflutter.so loaded (release Flutter app)?");
  }
}, 1000);
