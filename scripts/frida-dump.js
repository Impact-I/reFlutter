// frida-dump.js - reFlutter dump mode for Shorebird apps WITHOUT building an engine.
//
// ============================================================================
// README section draft (proposed addition to the frida part of the README):
//
// ## Dumping a Shorebird app without a patched engine
//
// Shorebird ships their own Flutter engine fork, and their private Dart SDK
// fork breaks reFlutter's engine builds - but the engine they *ship* inside
// the app's APK is unstripped. This script hooks the app's OWN libflutter.so
// at runtime and produces the same dump.dart JSONL a patched engine would
// have written (one JSON object per deserialized Dart function):
//
//   {"method_name": ..., "offset": "0x%016x", "library_url": ...,
//    "class_name": ..., "is_static": "true"/"false", "parameter_count": ...}
//
// It needs exactly ONE symbol from the engine - the deserialization hook
// point - and reads everything else straight out of the Dart object headers
// (see the layout table below), so it keeps working even though most VM
// accessor names live only in the engine's DWARF debug info, not in its
// symbol table. Requirements: an arm64 AOT app (like the engine patch, which
// targets the same kFullAOT branch), and the *unstripped* engine (the stock
// Shorebird artifact is; reFlutter's repacked copies are not - rebuild the
// APK with the stock lib/arm64-v8a/libflutter.so if needed).
//
// Usage (spawn mode is mandatory - the dump happens during isolate startup):
//   frida -D <device> -f <package> -l scripts/frida-dump.js
// The output lands at /data/data/<package>/dump.dart on the device.
// Pull it with `adb root && adb shell cat /data/data/<package>/dump.dart`
// and feed it to scripts/dump2disasm.py. Offsets are relative to the Dart
// instructions image start - same convention as the engine dumps (see
// dump2disasm.py, _kDartIsolateSnapshotInstructions / _kDartSnapshotText).
//
// Caveats: AOT only. Every isolate (re)load appends to the same file, exactly
// like the engine's fopen("a+") behaviour. Offsets are byte-identical to the
// engine patch's; names differ by design: the patch writes the scrubbed
// UserVisibleNameCString forms (private-key suffix stripped), we write the raw
// name_ strings - same name plus a retained @<key> on private classes, which
// is strictly more information (see the SYM_POSTLOAD comment below).
//
// Divergences from the engine patch, verified on a live Shorebird snapshot
// (adversarial review, 2026-09-23):
//  - parameter_count: ~80% of functions on that snapshot share a 16-byte
//    Shorebird-appended signature stub (cid above the known FunctionType) -
//    this script prints 0 for those where the patch would read garbage out
//    of bounds. Treat parameter_count as UNKNOWN on Shorebird snapshots.
//  - ~14% of functions have a non-Class owner: we print "<not-a-class>" /
//    "<null>" (with "<null>" library_url); the patch would print accessor
//    output (or garbage) for the same cases. Offsets/names are unaffected.
// A successful dump always logs a summary line to stderr (entries + path);
// silence means no dump happened - check the DEBUG flag for the why.
// ============================================================================
//
// HOW IT WORKS (the why, per repo style):
//
// The engine patch this mirrors lives in reflutter/utils.py (~line 974): it
// splices a JSONL dumper into FunctionDeserializationCluster::PostLoad right
// after ASSERT(code->IsCode()). At that point every Function of the snapshot
// is deserialized and its Code is filled, but nothing has been moved yet.
// We replicate the same moment from outside via Frida.
//
// WHY RAW LAYOUT READS INSTEAD OF CALLING VM ACCESSORS
// (the false start this script survived): the shipped engine *does* contain
// all the accessor names - but only inside its DWARF sections (.debug_str is
// 60 MB of a 175 MB .so). They are debug strings, not symbols: the actual
// .symtab of the stock Shorebird artifact has every FIELD accessor inlined
// away - Function::name / Function::owner / Function::code / Code::entry_point
// / Array::Length / String::ToCString are all ABSENT (verified by parsing the
// ELF, engine ff3aeea997). What survives are the out-of-line heavyweights:
// the hook point itself, plus name formatters we deliberately don't use
// (Class::UserVisibleNameCString etc. - they'd emit the scrubbed visible
// name, not the raw name_ the engine patch writes; see Caveats).
//   _ZN4dart30FunctionDeserializationCluster8PostLoadEPNS_12DeserializerERKNS_5ArrayE
// Frida's Module.enumerateSymbols sees .symtab/.dynsym only, never DWARF, so
// an accessor-calling version of this script fails with "missing symbols"
// even though `strings -a` finds every name. Hence: hook PostLoad (the one
// mandatory symbol) and read every field directly with the offsets below.
//
// Offset provenance: sb engine ff3aeea9 -> vanilla Flutter 3.47.5
// (flutter/flutter DEPS at engine commit af7e796e pins dart_revision
// b530c21f = Dart 3.13.4; Shorebird's private dart-sdk fork cf944b9e is
// built on top of it and only touches the entry-point plumbing -
// Deserializer::EntryPoints::EnsureUnwrapped et al. - not object layouts).
// All layouts below are arm64 + DART_PRECOMPILED_RUNTIME + PRODUCT +
// DART_COMPRESSED_POINTERS, i.e. a normal Android arm64 release engine:
//
//   UntaggedObject:   tags_ @0  (uword); cid = (tags >> 12) & 0xFFFFF
//   Object wrapper:   vptr @0 (Object has a virtual dtor/HandleTag),
//                     ptr_ @8  -> a "handle" is just {vptr, ptr}
//   DeserializationCluster: vptr @0, name_ @8, is_canonical_ @16,
//                     is_immutable_ @17, start_index_ @24, stop_index_ @32
//   UntaggedArray:    type_arguments @8, length @12 (compressed Smi, >>1),
//                     data[] @16 (32-bit compressed slots)
//   UntaggedFunction: entry_point_ @8, unchecked_entry_point_ @16,
//                     name_ @24, owner_ @28, signature_ @32, data_ @36,
//                     ic_data_array_or_bytecode_ @40, code_ @44,
//                     kind_tag_ @48 (u32; "See Function::KindTagBits")
//   UntaggedCode:     entry_point_ @8, monomorphic_entry_point_ @16,
//                     unchecked_entry_point_ @24,
//                     monomorphic_unchecked_entry_point_ @32,
//                     object_pool_ @40, instructions_ @48, owner_ @56
//                     (object_pool/instructions/owner are full 8-byte
//                      POINTER_FIELDs - generated code reads them as uwords)
//   UntaggedInstructionsTable: code_objects @8 (full POINTER_FIELD),
//                     length_ @16, rodata_ @24, start_pc_ @32, end_pc_ @40.
//                     (The leading code_objects pointer is easy to miss and
//                     shifts every following field by 8 - reading start_pc_
//                     at @24 silently yields rodata_, which produced offsets
//                     uniformly shifted by the rodata size; the batch gates
//                     caught it.)
//                     Data header = 4x u32, then
//                     DataEntry{u32 pc_offset, u32 stack_map_offset}[]
//   UntaggedWeakSerializationReference: target_ @8, replacement_ @12
//   UntaggedString:   length @8 (compressed Smi), data @16
//                     (OneByteString=Latin-1, TwoByteString=UTF-16).
//                     With HASH_IN_OBJECT_HEADER (defined on 64-bit,
//                     runtime/vm/globals.h) there is no hash field, and
//                     OPEN_ARRAY_START hands out the data after the struct
//                     is padded to its 8-byte alignment: bytes @12..16 are
//                     structural padding, the characters start at @16.
//                     (Reading the !HASH_IN_OBJECT_HEADER layout - hash@8,
//                     length@12, data@16 - or the padded-to-12 variant both
//                     yield empty or NUL-padded names; the offsets here are
//                     the empirically confirmed ones.)
//   UntaggedFunctionType: packed_parameter_counts_ @48 (u32): bit 0 implicit
//                     params, bit 1 has-named-optional, bits 2-15 num fixed,
//                     bits 16-29 num optional
//   UntaggedClass:    name_ @8, ..., library_ @36 (compressed)
//   UntaggedLibrary:  name_ @8, url_ @12 (compressed)
//   cid values (class_id.h at b530c21f): Class=5, Function=7, Library=13,
//                     WSR=16, Code=18, InstructionsTable=22,
//                     FunctionType=50, OneByteString=94, TwoByteString=95
//
// Function::is_static, for the record, is kind_tag_ bit 16. Derivation (all
// in object.h/raw_object.h/method_recognizer.h at the pin): KindBits occupy
// bits 0..4 (BitLength(kRecordFieldGetter=16) = 5), RecognizedBits bits
// 5..13 (BitLength(459 recognizers) = 9), ModifierBits bits 14..15
// (BitLength(kAsyncGen=3) = 2), and each FOR_EACH_FUNCTION_KIND_BIT boolean
// starts at ModifierBits::kNextBit - Static is the first of them, and the 15
// bools + Inlinable exactly fill bits 16..31 of the u32, which is a nice
// consistency proof. So is_static = (kind_tag_ >> 16) & 1.
//
// Compressed pointers: heap slots hold 32-bit offsets from a 4GB-aligned
// base, so decompress(slot) = (any_heap_object & 0xFFFFFFFF00000000) | slot.
// We bootstrap the base from the `refs` Array object address handed to
// PostLoad. Fields we consume are either full 8-byte POINTER_FIELDs
// (Code::owner_) or compressed slots we decompress ourselves; nothing is
// double-decompressed.
//
// offset semantics, matching the engine patch byte for byte:
//   reflutter_base = IT.EntryPointAt(0) - IT.rodata()->entries()[0].pc_offset
// and since InstructionsTable::EntryPointAt(i) = start_pc_ + entries[i]
// .pc_offset (object.cc), that whole expression *is* start_pc_. The patch
// hooks nothing to get it: it reads it off the deserializer's
// InstructionsTable. We do the same by scanning the Deserializer object's
// own memory for the one handle whose target object has cid 22 - layout and
// false-positive proof (there is exactly one InstructionsTable per snapshot,
// and candidates are validated by tagged-bit + cid + pc sanity), and immune
// to Deserializer's compiler-dependent member layout. InstructionsTable::New
// would also tell us start_pc (arg 2) but its symbol is DWARF-only, so no.
//
// The WSR filter (tree-shaken placeholder code): the patch keeps a function
// only if WSR::Unwrap(code->untag()->owner()) == func. In the AOT runtime
// (not the precompiler) Unwrap compiles to identity, but deferred/loading-unit
// snapshots can still carry WSRs, so we mirror the precompiler semantics by
// hand: unwrap one level through UntaggedWSR::target_ when the cid matches.
// ============================================================================

"use strict";

// The stock Shorebird engine artifact is unstripped, so this works unmodified
// against it; set to true only if you are debugging the script itself.
var DEBUG = false;

function logErr(msg) {
  // stdout stays quiet by default (repo rule); failures still surface.
  console.error("[frida-dump] " + msg);
}
function logDbg(msg) {
  if (DEBUG) console.log("[frida-dump] " + msg);
}

// --- derived constants (see the header comment for their provenance) -------
var CID = {
  kClassCid: 5,
  kFunctionCid: 7,
  kLibraryCid: 13,
  kWeakSerializationReferenceCid: 16,
  kCodeCid: 18,
  kInstructionsTableCid: 22,
  kFunctionTypeCid: 50,
  kOneByteStringCid: 94,
  kTwoByteStringCid: 95,
};

var OFF = {
  cluster_start_index: 24,
  cluster_stop_index: 32,
  array_length: 12, // compressed Smi slot
  array_data: 16,
  func_name: 24, // compressed slot
  func_owner: 28, // compressed slot
  func_signature: 32, // compressed slot (FunctionType)
  func_code: 44, // compressed slot
  func_kind_tag: 48, // u32; static bit = 16
  code_entry_point: 8,
  code_owner: 56, // full pointer
  wsr_target: 8, // compressed slot
  it_code_objects: 8, // full pointer (the field that shifts the rest)
  it_length: 16,
  it_rodata: 24,
  it_start_pc: 32,
  it_end_pc: 40,
  ftype_packed_counts: 48, // u32 (fixed bits 2-15, optional bits 16-29)
  cls_name: 8, // compressed slot
  cls_library: 36, // compressed slot
  lib_url: 12, // compressed slot
  string_length: 8, // compressed Smi slot (HASH_IN_OBJECT_HEADER layout)
  string_data: 16, // after the 8-byte-alignment struct padding
  handle_ptr: 8, // Object wrapper: vptr @0, ptr_ @8
};

// The one symbol this script needs: the splice point itself.
//
// Name source - the one place we knowingly diverge from the engine patch:
// the patch writes func.UserVisibleNameCString() / rClass
// .UserVisibleNameCString(), which are String::ScrubName over the raw name,
// i.e. the @<private-key> suffix is stripped (_OverlayEntryWidgetState@15531
// ... becomes _OverlayEntryWidgetState). The stock artifact does export
// Class::UserVisibleNameCString and an earlier revision called it per entry;
// we read name_ raw instead for two reasons: a NativeFunction call per entry
// cost seconds across an 8k-function cluster, and the raw names are strictly
// more information (the @key disambiguates same-named private classes from
// different libraries). Public names are byte-identical either way; only
// private ones show the extra @<key> here.
var SYM_POSTLOAD =
  "_ZN4dart30FunctionDeserializationCluster8PostLoadEPNS_12DeserializerERKNS_5ArrayE";

// Env-specific survival: on Android 16 emulators the GL stack dies inside
// impeller::egl::Display::CreatePixelBufferSurface a few seconds into startup
// (the app itself runs fine without Frida - attach overhead tips the racy
// emulator EGL init over the edge). That SIGSEGV kills the process mid-dump.
// Returning null there is safe by design: flutter's AndroidSurfaceDynamic-
// Impeller exists precisely to fall back to Skia when an Impeller surface
// cannot be created. Gated on ro.kernel.qemu so real devices (where the call
// must keep working) are untouched. Set to false if you want a pristine app.
var BYPASS_EMULATOR_IMPELLER_BUG = true;
var SYM_IMPELLER_PIXBUF_SURFACE =
  "_ZN8impeller3egl7Display24CreatePixelBufferSurfaceERKNS0_6ConfigEmm";

// Same env, second symptom: with a debugger attached the emulator's GL stack
// cannot initialize at all (EGL_NOT_INITIALIZED), and the system RenderThread
// calls abort() - killing the whole process, dump included, seconds into
// startup. Parking the aborting thread (instead of dying) keeps the dart/UI
// threads alive; the dump finishes and the app just renders nothing. Only
// active on emulators, same gate as above.
var PARK_EMULATOR_ABORTS = true;

// How far into the Deserializer object to hunt for the InstructionsTable
// handle. The Deserializer is a plain C++ object a few hundred bytes long
// (GrowableArrays, counters, a profile-writer pointer...); the reference is
// nowhere near this bound, but scanning is cheap so leave headroom.
var DESERIALIZER_SCAN_BYTES = 0x600;

// --- state -----------------------------------------------------------------
var g = {
  outPath: null,
  hooked: false,
  parkAborts: undefined,
  abortsParked: false,
};

// --- small helpers ----------------------------------------------------------

// Heap object pointers in the Dart VM are TAGGED: ObjectPtr = &UntaggedObject
// + 1, and every field offset in the table below is relative to the untagged
// base. All readers here take tagged pointers and untag once - getting this
// wrong reads everything shifted by one byte (the failure this script first
// shipped with: a refs length that looked like float bits).
function untag(objPtr) {
  return objPtr.sub(1);
}

// Decompress a 32-bit slot against the 4GB-aligned heap base.
function decompress(base, slot) {
  return base.or(slot);
}

// cid from a tagged ObjectPtr: tags_ is a uword at untagged offset 0 and the
// cid lives in its bits 12..31.
function cidOf(objPtr) {
  return Number(untag(objPtr).readU64().shr(12).and(0xfffff));
}

function smiOf(slot) {
  // compressed Smi: value = int32(slot) >> 1
  return slot >> 1;
}

// Read a compressed pointer field at untagged offset `off` of a tagged
// ObjectPtr and decompress it in one step.
function readComp(base, objPtr, off) {
  var slot = untag(objPtr).add(off).readU32();
  if (slot === 0) return ptr(0);
  return decompress(base, ptr(slot));
}

// Read a Dart String object into a JS string. String::ToCString is not
// resolvable in the shipped engine, so we read the character data ourselves.
// OneByteStrings hold Latin-1, not UTF-8, so decode byte-wise; almost all
// real names/urls are ASCII, this just keeps the rest honest.
function readDartString(objPtr) {
  if (objPtr.isNull()) return "<null>";
  var cid = cidOf(objPtr);
  var len = smiOf(untag(objPtr).add(OFF.string_length).readS32());
  if (len < 0 || len > 10 * 1024 * 1024) return "<bad-length>";
  if (cid === CID.kOneByteStringCid) {
    var bytes = untag(objPtr).add(OFF.string_data).readByteArray(len);
    var view = new Uint8Array(bytes);
    var out = "";
    for (var i = 0; i < view.length; i++) out += String.fromCharCode(view[i]);
    return out;
  } else if (cid === CID.kTwoByteStringCid) {
    // length is in UTF-16 code units
    return untag(objPtr).add(OFF.string_data).readUtf16String(len);
  }
  return "<not-a-string:" + cid + ">";
}

// JSON escaping matching dart's JSONWriter (quotes, backslash, control
// chars); library urls and scrubbed names can legally contain quotes and
// newlines, and a single bad line would not just corrupt itself but every
// later consumer that isn't as tolerant as dump2disasm.py.
function jsonEscape(s) {
  var out = "";
  for (var i = 0; i < s.length; i++) {
    var c = s.charCodeAt(i);
    if (c === 0x22) out += '\\"';
    else if (c === 0x5c) out += "\\\\";
    else if (c === 0x08) out += "\\b";
    else if (c === 0x0c) out += "\\f";
    else if (c === 0x0a) out += "\\n";
    else if (c === 0x0d) out += "\\r";
    else if (c === 0x09) out += "\\t";
    else if (c < 0x20) {
      var h = c.toString(16);
      while (h.length < 4) h = "0" + h;
      out += "\\u" + h;
    } else out += s[i];
  }
  return out;
}

// Mirror of the C++ JSONWriter property order and value types: every property
// is a JSON string here, parameter_count included (the engine patch passes
// std::to_string(...).c_str() to PrintProperty). "0x%016x" = 16 hex digits.
function emitLine(methodName, offsetHex, libraryUrl, className, isStatic, nParams) {
  return (
    '{"method_name":"' +
    jsonEscape(methodName) +
    '","offset":"' +
    offsetHex +
    '","library_url":"' +
    jsonEscape(libraryUrl) +
    '","class_name":"' +
    jsonEscape(className) +
    '","is_static":"' +
    (isStatic ? "true" : "false") +
    '","parameter_count":"' +
    nParams.toString() +
    '"}'
  );
}

// libc/linker lookups. Frida 17 removed Module.getExportByName(null, ...)
// (the null-module global search); getGlobalExportByName is the replacement,
// with an instance-method fallback for older clients.
function findGlobalExport(name) {
  if (typeof Module.getGlobalExportByName === "function") {
    try {
      return Module.getGlobalExportByName(name);
    } catch (e) {
      return null;
    }
  }
  var mods = Process.enumerateModules();
  for (var i = 0; i < mods.length; i++) {
    try {
      var a = mods[i].findExportByName(name);
      if (a) return a;
    } catch (e) {
      /* keep looking */
    }
  }
  return null;
}

// /proc/self/cmdline gives the application id - the same trick the engine
// patch uses to find /data/data/<pkg>/dump.dart.
function packageName() {
  var fopen = new NativeFunction(findGlobalExport("fopen"), "pointer", [
    "pointer",
    "pointer",
  ]);
  var fgets = new NativeFunction(findGlobalExport("fgets"), "pointer", [
    "pointer",
    "int",
    "pointer",
  ]);
  var fclose = new NativeFunction(findGlobalExport("fclose"), "int", [
    "pointer",
  ]);
  var fp = fopen(
    Memory.allocUtf8String("/proc/self/cmdline"),
    Memory.allocUtf8String("r")
  );
  if (fp.isNull()) return null;
  var buf = Memory.alloc(256);
  var ok = fgets(buf, 256, fp);
  fclose(fp);
  if (ok.isNull()) return null;
  return buf.readCString().replace(/\0.*$/, "").trim();
}

// --- symbol resolution -------------------------------------------------------

function findModule() {
  var mods = Process.enumerateModules();
  for (var i = 0; i < mods.length; i++) {
    if (mods[i].name === "libflutter.so") return mods[i];
  }
  return null;
}

// One pass over the (huge) symtab for the symbols we hook. These are internal
// .symtab symbols, NOT .dynsym exports, so Module.getExportByName can't see
// them - and a stripped engine won't have them at all, which is the "repacked
// copy" failure mode.
function findSymbols(mod) {
  var want = {};
  want[SYM_POSTLOAD] = "postLoad";
  if (BYPASS_EMULATOR_IMPELLER_BUG) {
    want[SYM_IMPELLER_PIXBUF_SURFACE] = "impellerPixbuf";
  }
  var found = {};
  var symbols = mod.enumerateSymbols();
  for (var i = 0; i < symbols.length; i++) {
    var key = want[symbols[i].name];
    if (key !== undefined && found[key] === undefined) {
      found[key] = symbols[i].address;
    }
  }
  if (found.postLoad === undefined) return null;
  return found;
}

function runningInEmulator() {
  var f = findGlobalExport("__system_property_get");
  if (f === null) return false;
  var getProp = new NativeFunction(f, "int", ["pointer", "pointer"]);
  var buf = Memory.alloc(92); // PROP_VALUE_MAX
  getProp(Memory.allocUtf8String("ro.kernel.qemu"), buf);
  return buf.readCString() === "1";
}

// --- the instructions-image base ---------------------------------------------

// Find start_pc_ by scanning the Deserializer's own memory for the
// InstructionsTable handle. See the header comment for why this equals the
// engine patch's reflutter_base. Returns {base, imageSize} or null.
function findTextBase(deserializer) {
  for (var off = 0; off < DESERIALIZER_SCAN_BYTES; off += 8) {
    var h;
    try {
      h = deserializer.add(off).readPointer();
    } catch (e) {
      break; // ran off the mapping - nothing more to scan
    }
    if (h.isNull() || h.compare(ptr(0x10000)) < 0) continue;
    var obj;
    try {
      obj = h.add(OFF.handle_ptr).readPointer();
    } catch (e) {
      continue; // qword points outside mapped memory - not a handle
    }
    // ObjectPtrs are tagged (bit 0 = 1); anything else is not a handle.
    if (obj.and(1).toInt32() !== 1) continue;
    var untagged;
    var cid;
    try {
      cid = cidOf(obj); // takes a tagged pointer and untags internally
      untagged = untag(obj);
    } catch (e) {
      continue;
    }
    if (cid !== CID.kInstructionsTableCid) continue;
    var startPc = untagged.add(OFF.it_start_pc).readPointer();
    var endPc = untagged.add(OFF.it_end_pc).readPointer();
    // NativePointer has no greaterThan() - compare() is the API here.
    if (startPc.isNull() || endPc.compare(startPc) <= 0) continue;
    // start_pc must land in a readable mapping (the mapped instructions
    // image). Without this a garbage qword that happens to point at a tagged
    // cid-22 pattern would poison every offset.
    var range = Process.findRangeByAddress(startPc);
    if (range === null || range.protection.indexOf("r") === -1) continue;
    logDbg(
      "instructions image: base " + startPc + " size " + endPc.sub(startPc)
    );
    return { base: startPc, imageSize: Number(endPc.sub(startPc)) };
  }
  return null;
}

// --- the dump itself ---------------------------------------------------------

function dumpCluster(startIndex, stopIndex, refsHandle, heapBase, image) {
  // refs is a const Array& -> pointer to an Array handle (vptr @0, ptr_ @8).
  var refsPtr = refsHandle.add(OFF.handle_ptr).readPointer();
  var len = smiOf(untag(refsPtr).add(OFF.array_length).readS32());
  var data = untag(refsPtr).add(OFF.array_data);

  // Layout sanity before we touch anything: the ref array must cover the
  // cluster's [start, stop) window. Wrong struct offsets would otherwise
  // surface as a crash mid-scan; abort loudly instead.
  if (!(len > 0 && len < 100 * 1000 * 1000)) {
    logErr("implausible refs length " + len + " - aborting (offset mismatch?)");
    return null;
  }
  if (!(startIndex >= 0 && stopIndex >= startIndex && stopIndex <= len)) {
    logErr(
      "implausible cluster range [" +
        startIndex +
        ", " +
        stopIndex +
        ") for refs length " +
        len +
        " - aborting (offset mismatch?)"
    );
    return null;
  }

  var lines = [];
  var written = 0;
  var sampled = 0;
  var negativeOffsets = 0;
  var oversizeOffsets = 0;
  var badEntries = 0;
  var baseGatesPassed = false;
  for (var i = startIndex; i < stopIndex; i++) {
    try {
      var slot = data.add(i * 4).readU32();
      if (slot === 0) continue; // null ref
      var funcPtr = decompress(heapBase, ptr(slot));

      // Cheap layout guard: sample the cid every 512 refs. If our Function
      // offsets were wrong, the field reads below would return garbage
      // rather than crash - a wrong cid here is the earliest, safest tell.
      if (i % 512 === 0) {
        sampled++;
        if (cidOf(funcPtr) !== CID.kFunctionCid) {
          logErr(
            "ref " + i + " is not a Function (cid mismatch) - aborting batch"
          );
          return null;
        }
      }

      // code = func.ptr()->untag()->code() - a plain field read in AOT.
      var codePtr = readComp(heapBase, funcPtr, OFF.func_code);
      if (codePtr.isNull()) continue;
      if (cidOf(codePtr) !== CID.kCodeCid) continue;

      // WSR::Unwrap(code->untag()->owner()) == func  - tree-shake filter.
      // In the AOT runtime Unwrap is the identity, but mirror the precompiler
      // semantics so loading-unit snapshots behave like the engine patch.
      var owner = untag(codePtr).add(OFF.code_owner).readPointer();
      if (
        !owner.isNull() &&
        cidOf(owner) === CID.kWeakSerializationReferenceCid
      ) {
        owner = readComp(heapBase, owner, OFF.wsr_target);
      }
      if (owner.isNull() || !owner.equals(funcPtr)) continue;

      // --- all reads below are only reached for emitted functions ---------

      // method_name: the raw Function::name_ string (Function::
      // UserVisibleNameCString is DWARF-only in this engine; see the
      // SYM_POSTLOAD comment for the name-shape tradeoff).
      var name = readDartString(readComp(heapBase, funcPtr, OFF.func_name));

      // The Function's owner is the Class (the Code's owner above was only
      // the tree-shake filter - the engine patch reads rClass = func.Owner()
      // at this exact spot too).
      var clsPtr = readComp(heapBase, funcPtr, OFF.func_owner);

      // class_name: raw Class::name_. The patch's rClass
      // .UserVisibleNameCString() call produces the scrubbed form for private
      // classes (its PRODUCT path is GenerateUserVisibleName, which strips the
      // @<key>); we keep the key. Public classes are identical either way.
      var className;
      if (clsPtr.isNull() || cidOf(clsPtr) !== CID.kClassCid) {
        className = "<not-a-class>";
      } else {
        className = readDartString(readComp(heapBase, clsPtr, OFF.cls_name));
      }

      // library_url: Class::library_ -> Library::url_
      var libraryUrl = "<null>";
      var libPtr = readComp(heapBase, clsPtr, OFF.cls_library);
      if (!libPtr.isNull() && cidOf(libPtr) === CID.kLibraryCid) {
        libraryUrl = readDartString(readComp(heapBase, libPtr, OFF.lib_url));
      }

      // is_static: kind_tag_ bit 16 (derivation in the header comment)
      var isStatic =
        (untag(funcPtr).add(OFF.func_kind_tag).readU32() >> 16) & 1;

      // parameter_count: fixed + optional from the signature's packed counts.
      // Guards: the signature slot is only read when it really is a
      // FunctionType, otherwise count stays 0 like a malformed signature.
      var nParams = 0;
      var sigPtr = readComp(heapBase, funcPtr, OFF.func_signature);
      if (!sigPtr.isNull() && cidOf(sigPtr) === CID.kFunctionTypeCid) {
        var packed = untag(sigPtr).add(OFF.ftype_packed_counts).readU32();
        nParams =
          ((packed >> 2) & 0x3fff) + ((packed >> 16) & 0x3fff);
      }

      // offset = entry_point - (EntryPointAt(0) - entries[0].pc_offset)
      //        = entry_point - start_pc                    (see header comment)
      var entry = untag(codePtr).add(OFF.code_entry_point).readPointer();
      var rel = entry.sub(image.base);
      if (entry.compare(image.base) < 0) {
        // would print as a huge wrapped %016x in C too - emit it the same way,
        // but keep count so a systematically wrong base is caught below
        negativeOffsets++;
      } else if (Number(rel) >= image.imageSize) {
        oversizeOffsets++;
      }
      var offsetHex = "0x" + rel.toString(16).padStart(16, "0");
      lines.push(
        emitLine(name, offsetHex, libraryUrl, className, isStatic, nParams)
      );
      if (DEBUG && lines.length <= 3) {
        var ns = readComp(heapBase, funcPtr, OFF.func_name);
        logDbg(
          "slots i=" +
            i +
            " nameStr=" +
            ns +
            " lenSlot=" +
            (ns.isNull() ? -1 : untag(ns).add(OFF.string_length).readU32()) +
            " cid=" +
            (ns.isNull() ? -1 : cidOf(ns))
        );
      }
      if (DEBUG && lines.length <= 5) {
        logDbg(
          "entry " +
            i +
            ": " +
            lines[lines.length - 1] +
            " [func=" +
            funcPtr +
            " code=" +
            codePtr +
            " cls=" +
            clsPtr +
            " entry=" +
            entry +
            "]"
        );
      } else if (DEBUG && (written + lines.length) % 1024 === 0) {
        logDbg("progress: " + (written + lines.length) + " entries at ref " + i);
      }
      // Before the FIRST flush, run the batch gates on what we have so a
      // systematically wrong base is not persisted chunk by chunk; afterwards
      // every WRITE_CHUNK lines go straight to disk (see writeLines).
      if (lines.length >= WRITE_CHUNK && !baseGatesPassed) {
        if (negativeOffsets > lines.length / 10 || oversizeOffsets > lines.length / 10) {
          logErr(
            negativeOffsets +
              " negative / " +
              oversizeOffsets +
              " oversize of " +
              lines.length +
              " offsets - instructions base looks wrong, discarding batch"
          );
          return null;
        }
        baseGatesPassed = true;
      }
      if (baseGatesPassed && lines.length >= WRITE_CHUNK) {
        writeLines(lines);
        written += lines.length;
        lines = [];
      }
    } catch (e) {
      // A single unreadable ref must not kill the batch (or the app); count
      // it and move on. A systematic layout mismatch shows up in the guards
      // above, not here.
      badEntries++;
      logDbg("ref " + i + " unreadable: " + e);
    }
  }
  logDbg(
    "sampled " +
      sampled +
      " cids, " +
      badEntries +
      " bad refs, " +
      negativeOffsets +
      " negative / " +
      oversizeOffsets +
      " oversize offsets in [" +
      startIndex +
      ", " +
      stopIndex +
      ")"
  );
  return lines;
}

// Flush in chunks rather than once per batch: the engine patch writes every
// entry with its own fopen("a+"), and on a device where the app dies seconds
// into startup (impeller/EGL misbehaving under an emulator GL stack), a dump
// buffered until the end of the cluster simply never lands.
var WRITE_CHUNK = 512;
var writeFile = null;
var g_totalEntries = 0;

function writeLines(lines) {
  if (lines.length === 0) return;
  if (writeFile === null) {
    // Frida's File maps to fopen; "a" appends like the engine's fopen("a+").
    writeFile = new File(g.outPath, "a");
  }
  writeFile.write(lines.join("\n") + "\n");
  writeFile.flush();
  g_totalEntries += lines.length;
}

// --- hooking -----------------------------------------------------------------

function hookOnce(mod) {
  if (g.hooked) return;
  g.hooked = true;

  var addr = findSymbols(mod);
  if (addr === null) {
    logErr(
      "PostLoad symbol not found in " +
        mod.name +
        " (stripped engine? rebuild the APK with the stock unstripped libflutter.so)"
    );
    return;
  }
  g.addr = addr;

  if (addr.impellerPixbuf !== undefined && runningInEmulator()) {
    // std::unique_ptr returns as a single pointer in x0; null makes the
    // caller fall back to Skia instead of dying inside the emulator's GL
    // stack while the dump is still being written.
    var fakePixbuf = new NativeCallback(
      function () {
        return ptr(0);
      },
      "pointer",
      ["pointer", "pointer", "pointer", "pointer"] // this, const Config&, w, h
    );
    Interceptor.replace(addr.impellerPixbuf, fakePixbuf);
    logDbg("emulator detected - impeller pixel-buffer surface bypassed");
  }

  if (PARK_EMULATOR_ABORTS && runningInEmulator()) {
    var libcAbort = findGlobalExport("abort");
    if (libcAbort !== null) {
      g.parkAborts = function () {
        if (g.abortsParked) return;
        g.abortsParked = true;
        Interceptor.replace(
          libcAbort,
          new NativeCallback(
            function () {
              // Park this thread forever: it called abort(), which by
              // contract never returns. Blocking here keeps the rest of the
              // process up (the dump thread included) without ever resuming
              // into a noreturn function.
              for (;;) {
                Thread.sleep(3600);
              }
            },
            "void",
            []
          )
        );
        logDbg("abort() parked from here on");
      };
    }
  }

  var pkg = packageName();
  if (pkg === null || pkg.length === 0) {
    logErr("could not read application id from /proc/self/cmdline");
    return;
  }
  g.outPath = "/data/data/" + pkg + "/dump.dart";
  logDbg("dump target: " + g.outPath);

  Interceptor.attach(addr.postLoad, {
    onEnter: function (args) {
      try {
        var cluster = args[0]; // FunctionDeserializationCluster*
        var deserializer = args[1]; // Deserializer*
        var refsHandle = args[2]; // const Array&

        var start = Number(cluster.add(OFF.cluster_start_index).readS64());
        var stop = Number(cluster.add(OFF.cluster_stop_index).readS64());

        // Bootstrap the 4GB-aligned heap base from the refs Array object
        // itself (a real heap object): decompress(slot) = base | slot.
        var refsPtr = refsHandle.add(OFF.handle_ptr).readPointer();
        var heapBase = refsPtr.and(ptr("0xFFFFFFFF00000000"));

        if (DEBUG) {
          logDbg(
            "cluster=" +
              cluster +
              " d=" +
              deserializer +
              " refsHandle=" +
              refsHandle
          );
          try {
            logDbg(
              "refsPtr=" +
                refsPtr +
                " tags=" +
                refsPtr.readU64() +
                " cid=" +
                cidOf(refsPtr) +
                " lenSlot=0x" +
                untag(refsPtr).add(OFF.array_length).readU32().toString(16) +
                " start=" +
                start +
                " stop=" +
                stop
            );
          } catch (e2) {
            logDbg("refs probe failed: " + e2);
          }
        }

        var image = findTextBase(deserializer);
        if (image === null) {
          // e.g. the VM-snapshot pass of PostLoad, which has no instructions
          // table (AOT app snapshots do; that's the pass we want anyway).
          logDbg("no InstructionsTable reachable from this deserializer - skipping");
          return;
        }

        var lines = dumpCluster(start, stop, refsHandle, heapBase, image);
        if (lines !== null && lines.length > 0) {
          writeLines(lines); // final partial chunk
        }
        if (writeFile !== null) {
          writeFile.close();
          writeFile = null;
        }
        // always announce the result on stderr (not DEBUG-gated): silence
        // should mean "no dump", never a quiet success
        if (g_totalEntries > 0) {
          logErr("[frida-dump] wrote " + g_totalEntries + " entries to " + g.outPath + " - pull it and run scripts/dump2disasm.py");
        } else {
          logErr("[frida-dump] completed with 0 entries - engine layout mismatch? (see DEBUG)");
        }
      } catch (e) {
        // never break the app's startup because of us
        logErr("PostLoad hook failed: " + (e && e.stack ? e.stack : e));
      }
      // We are inside the dump window now - only from here on is parking
      // aborts safe (see PARK_EMULATOR_ABORTS).
      if (g.parkAborts !== undefined) g.parkAborts();
    },
  });
  logDbg("hooks installed");
}

// --- entry point ---------------------------------------------------------------
// Spawn mode (-f) is the intended use: libflutter.so is not loaded yet when
// the script starts, so wait for the dynamic linker. If we attached to an
// already-running process the PostLoad moment is gone - say so instead of
// failing silently.

function libflutterLoaded() {
  return findModule() !== null;
}

if (libflutterLoaded()) {
  // Still install the hooks (a *second* snapshot load may yet happen), but
  // the main dump moment of THIS process is already gone.
  hookOnce(findModule());
  logErr(
    "libflutter.so was already loaded - the snapshot deserialization of the " +
      "running isolate has passed. Use spawn mode: " +
      "frida -D <device> -f <package> -l scripts/frida-dump.js"
  );
} else {
  var linkerSeen = {};
  ["android_dlopen_ext", "__dl_android_dlopen_ext", "dlopen"].forEach(
    function (name) {
      var addr = findGlobalExport(name);
      if (addr === null || linkerSeen[name]) return;
      linkerSeen[name] = true;
      Interceptor.attach(addr, {
        onEnter: function (args) {
          try {
            var p = args[0];
            this.path = p.isNull() ? "" : p.readCString();
          } catch (e) {
            this.path = "";
          }
        },
        onLeave: function () {
          if (
            this.path &&
            this.path.indexOf("libflutter.so") !== -1 &&
            !g.hooked &&
            libflutterLoaded()
          ) {
            // The engine is mapped; its VM is not initialized yet, but our
            // hooks only fire at snapshot load, which comes later.
            hookOnce(findModule());
          }
        },
      });
    }
  );
}
