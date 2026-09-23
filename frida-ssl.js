// frida -U -f <package> -l frida-ssl.js
//
// Runtime SSL bypass for Flutter Android apps - NO repackaging needed.
// Locates boringssl's ssl_crypto_x509_session_verify_cert_chain inside the
// loaded libflutter.so and patches it to return true, so any certificate
// chain is accepted and a local proxy (Burp etc.) intercepts the traffic.
//
// Resolution: Module.enumerateSymbols() reads the engine's .symtab - the
// target is internal-linkage (static in ssl_x509.cc), so it never appears
// in .dynsym. This works on engines that retain a symbol table: Shorebird
// engines, debug/profile builds, and current stock release engines. A
// fully stripped engine has no symtab and the script gives up with a
// message - use reFlutter repack mode for those.
//
// arm (thumb), arm64 and x64 are supported; other arches abort BEFORE
// writing anything (never writes bytes of the wrong ISA).

var SYMBOL_SUBSTRING = "ssl_crypto_x509_session_verify_cert_chain";
// arm64: mov w0, #1 ; ret
var BYPASS_ARM64 = [0x20, 0x00, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6];
// arm (thumb): movs r0, #1 ; bx lr
var BYPASS_ARM = [0x01, 0x20, 0x70, 0x47];
// x64: mov eax, 1 ; ret
var BYPASS_X64 = [0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3];

function bypassFor(arch) {
  if (arch === "arm64") return BYPASS_ARM64;
  if (arch === "arm") return BYPASS_ARM;
  if (arch === "x64" || arch === "ia32") return BYPASS_X64;
  return null;
}

function stripThumbBit(address) {
  // symtab entries for thumb functions carry bit 0; the code bytes live at
  // the even address below it
  return address.and(ptr("0xfffffffe"));
}

function tryPatchAt(module, address, bytes, why) {
  try {
    Memory.patchCode(address, bytes.length, function (ptr) {
      ptr.writeByteArray(bytes);
    });
    console.log("[+] patched verify_cert_chain at " + address + " (" + why + ")");
    return true;
  } catch (e) {
    console.log("[!] patch failed at " + address + ": " + e);
    return false;
  }
}

function findBySymtab(mod) {
  try {
    var symbols = mod.enumerateSymbols();
    for (var i = 0; i < symbols.length; i++) {
      if (symbols[i].name.indexOf(SYMBOL_SUBSTRING) !== -1 && symbols[i].type === "function") {
        return symbols[i].address;
      }
    }
  } catch (e) {
    console.log("[!] enumerateSymbols failed: " + e);
  }
  return null;
}

var BYPASS = bypassFor(Process.arch);
if (BYPASS === null) {
  console.log("[!] unsupported architecture '" + Process.arch + "' - not patching anything");
} else {
  var doPatch = function () {
    var mod = Process.findModuleByName("libflutter.so");
    if (mod === null) return false;
    var address = findBySymtab(mod);
    if (address === null) {
      console.log("[!] verify_cert_chain not found in libflutter.so symtab (stripped engine?)");
      return false;
    }
    if (Process.arch === "arm") address = stripThumbBit(address);
    return tryPatchAt(mod, address, BYPASS, "symtab/" + Process.arch);
  };

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
}
