import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart' as ffi;

import 'ffi.dart' as ffi;

extension Fixed32Array on Uint8List {
  Pointer<ffi.Fixed32Array> asFixed32ArrayPtr() {
    assert(length == 32);
    final ptr = ffi.malloc.allocate<Uint8>(32)..asTypedList(32).setAll(0, this);
    final arr = ffi.malloc<ffi.Fixed32Array>();
    arr.ref.buf = ptr;
    return arr;
  }
}

extension Uint8ListArray32 on Pointer<ffi.Fixed32Array> {
  Uint8List asUint8List() {
    final view = ref.buf.asTypedList(32);
    final builder = BytesBuilder(copy: false)..add(view);
    final bytes = builder.takeBytes();
    ffi.malloc.free(this);
    return bytes;
  }
}

extension Fixed64Array on Uint8List {
  Pointer<ffi.Fixed64Array> asFixed64ArrayPtr() {
    assert(length == 64);
    final ptr = ffi.malloc.allocate<Uint8>(64)..asTypedList(64).setAll(0, this);
    final arr = ffi.malloc<ffi.Fixed64Array>();
    arr.ref.buf = ptr;
    return arr;
  }
}

extension Uint8ListArray64 on Pointer<ffi.Fixed64Array> {
  Uint8List asUint8List() {
    final view = ref.buf.asTypedList(64);
    final builder = BytesBuilder(copy: false)..add(view);
    final bytes = builder.takeBytes();
    ffi.malloc.free(this);
    return bytes;
  }
}

extension SharedBuffer on Uint8List {
  Pointer<ffi.SharedBuffer> asSharedBufferPtr() {
    final extra = length > 10 ? 4 : 10;
    final cap = (length * extra) + 12; // 12 for nonce
    final ptr = ffi.malloc.allocate<Uint8>(cap)
      ..asTypedList(length).setAll(0, this);

    final buf = ffi.calloc<ffi.SharedBuffer>();
    buf.ref
      ..buf = ptr
      ..len = length
      ..cap = cap;
    return buf;
  }

  Pointer<ffi.SharedBuffer> asSharedBufferPtrExact() {
    final ptr = ffi.malloc.allocate<Uint8>(length)
      ..asTypedList(length).setAll(0, this);

    final buf = ffi.malloc<ffi.SharedBuffer>();
    buf.ref
      ..buf = ptr
      ..len = length
      ..cap = length;
    return buf;
  }
}

extension Uint8ListBuffer on Pointer<ffi.SharedBuffer> {
  Uint8List asUint8List() {
    final view = ref.buf.asTypedList(ref.len);
    final builder = BytesBuilder(copy: false)..add(view);
    final bytes = builder.takeBytes();
    ffi.malloc.free(this);
    return bytes;
  }
}
