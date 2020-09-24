import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart' as ffi;

import 'ffi.dart' as ffi;

extension Fixed32Array on Uint8List {
  Pointer<ffi.Fixed32Array> asFixed32ArrayPtr() {
    assert(length == 32);
    final ptr = ffi.allocate<Uint8>(count: 32)..asTypedList(32).setAll(0, this);

    final arr = ffi.allocate<ffi.Fixed32Array>();
    arr.ref.buf = ptr;
    return arr;
  }
}

extension Uint8ListArray on Pointer<ffi.Fixed32Array> {
  Uint8List asUint8List() {
    final view = ref.buf.asTypedList(32);
    final builder = BytesBuilder(copy: false)..add(view);
    final bytes = builder.takeBytes();
    ffi.free(ref.buf);
    ffi.free(this);
    return bytes;
  }
}

extension SharedBuffer on Uint8List {
  Pointer<ffi.SharedBuffer> asSharedBufferPtr() {
    final cap = (length * 4) + 12; // 12 for nonce
    final ptr = ffi.allocate<Uint8>(count: cap)
      ..asTypedList(length).setAll(0, this);

    final buf = ffi.allocate<ffi.SharedBuffer>();
    buf.ref
      ..buf = ptr
      ..len = length
      ..cap = cap;
    return buf;
  }
}

extension Uint8ListBuffer on Pointer<ffi.SharedBuffer> {
  Uint8List asUint8List() {
    final view = ref.buf.asTypedList(ref.len);
    final builder = BytesBuilder(copy: false)..add(view);
    final bytes = builder.takeBytes();
    ffi.free(ref.buf);
    ffi.free(this);
    return bytes;
  }
}
