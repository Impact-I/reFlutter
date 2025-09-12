//frida -U -f <package> -l frida.js

function hookFunc() {
  var dumpOffset = "0x20801C"; // _kDartIsolateSnapshotInstructions + code offset

  var argBufferSize = 150;

  let address;
  try {
      address = Module.findBaseAddress("libapp.so"); // libapp.so (Android) or App (IOS)
  }
  catch (e) {
      if (e instanceof TypeError && e.message === "not a function") {
          address = Process.findModuleByName("libapp.so");
          if (address != null) {
              address = address.base;
          }
      }
      else {
          throw e;
      }
  }
  console.log("\n\nbaseAddress: " + address.toString());

  var codeOffset = address.add(dumpOffset);
  console.log("codeOffset: " + codeOffset.toString());
  console.log("");
  console.log("Wait..... ");

  Interceptor.attach(codeOffset, {
    onEnter: function (args) {
      console.log("");
      console.log("--------------------------------------------|");
      console.log("\n    Hook Function: " + dumpOffset);
      console.log("");
      console.log("--------------------------------------------|");
      console.log("");

      for (var argStep = 0; argStep < 50; argStep++) {
        try {
          dumpArgs(argStep, args[argStep], argBufferSize);
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
}

function dumpArgs(step, address, bufSize) {
  var buf = Memory.readByteArray(address, bufSize);

  console.log(
    "Argument " +
      step +
      " address " +
      address.toString() +
      " " +
      "buffer: " +
      bufSize.toString() +
      "\n\n Value:\n" +
      hexdump(buf, {
        offset: 0,
        length: bufSize,
        header: false,
        ansi: false,
      }),
  );

  console.log("");
  console.log("----------------------------------------------------");
  console.log("");
}

setTimeout(hookFunc, 1000);
