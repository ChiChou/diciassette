# Frida 16 → 17 API Transformations

This document details all the API transformations performed by Diciassette.

## Table of Contents

1. [Module Export/Import APIs](#module-exportimport-apis)
2. [Module Base Address APIs](#module-base-address-apis)
3. [Module Initialization APIs](#module-initialization-apis)
4. [Module Symbol APIs](#module-symbol-apis)
5. [Memory Read/Write APIs](#memory-readwrite-apis)
6. [Optimization Strategy](#optimization-strategy)

---

## Module Export/Import APIs

### `Module.getExportByName(moduleName, exportName)`

**Before (Frida 16):**
```typescript
const open = Module.getExportByName('libc.so', 'open');
const close = Module.getExportByName('libc.so', 'close');
```

**After (Frida 17):**
```typescript
const libc_so = Process.getModuleByName('libc.so');
const open = libc_so.getExportByName('open');
const close = libc_so.getExportByName('close');
```

### `Module.findExportByName(moduleName, exportName)`

**Before (Frida 16):**
```typescript
const fn = Module.findExportByName('libm.so', 'sin');
```

**After (Frida 17):**
```typescript
const libm_so = Process.getModuleByName('libm.so');
const fn = libm_so.findExportByName('sin');
```

### `Module.getExportByName(null, exportName)` - Global Exports

**Before (Frida 16):**
```typescript
const exit = Module.getExportByName(null, 'exit');
```

**After (Frida 17):**
```typescript
const exit = Module.getGlobalExportByName('exit');
```

---

## Module Base Address APIs

### `Module.getBaseAddress(moduleName)`

**Before (Frida 16):**
```typescript
const base = Module.getBaseAddress('libc.so');
const offset = 0x1234;
const addr = base.add(offset);
```

**After (Frida 17):**
```typescript
const base = Process.getModuleByName('libc.so').base;
const offset = 0x1234;
const addr = base.add(offset);
```

### `Module.findBaseAddress(moduleName)`

**Before (Frida 16):**
```typescript
const base = Module.findBaseAddress('libm.so');
```

**After (Frida 17):**
```typescript
const base = Process.getModuleByName('libm.so').base;
```

---

## Module Initialization APIs

### `Module.ensureInitialized(moduleName)`

**Before (Frida 16):**
```typescript
Module.ensureInitialized('Foundation');
Module.ensureInitialized('UIKit');
```

**After (Frida 17):**
```typescript
Process.getModuleByName('Foundation').ensureInitialized();
Process.getModuleByName('UIKit').ensureInitialized();
```

---

## Module Symbol APIs

### `Module.getSymbolByName(moduleName, symbolName)`

**Before (Frida 16):**
```typescript
const sym = Module.getSymbolByName('libc.so', 'open');
```

**After (Frida 17):**
```typescript
const sym = Process.getModuleByName('libc.so').getSymbolByName('open');
```

### `Module.findSymbolByName(moduleName, symbolName)`

**Before (Frida 16):**
```typescript
const sym = Module.findSymbolByName('libc.so', 'close');
```

**After (Frida 17):**
```typescript
const sym = Process.getModuleByName('libc.so').findSymbolByName('close');
```

---

## Memory Read/Write APIs

### Memory Read APIs

All `Memory.read*()` methods are transformed to `ptr.read*()`:

**Before (Frida 16):**
```typescript
const addr = ptr('0x1234');
const u8 = Memory.readU8(addr);
const u16 = Memory.readU16(addr);
const u32 = Memory.readU32(addr);
const u64 = Memory.readU64(addr);
const s32 = Memory.readS32(addr);
const float = Memory.readFloat(addr);
const double = Memory.readDouble(addr);
const pointer = Memory.readPointer(addr);
const bytes = Memory.readByteArray(addr, 16);
const str = Memory.readUtf8String(addr);
```

**After (Frida 17):**
```typescript
const addr = ptr('0x1234');
const u8 = addr.readU8();
const u16 = addr.readU16();
const u32 = addr.readU32();
const u64 = addr.readU64();
const s32 = addr.readS32();
const float = addr.readFloat();
const double = addr.readDouble();
const pointer = addr.readPointer();
const bytes = addr.readByteArray(16);
const str = addr.readUtf8String();
```

### Memory Write APIs

All `Memory.write*()` methods are transformed to `ptr.write*()`:

**Before (Frida 16):**
```typescript
const addr = ptr('0x1234');
Memory.writeU8(addr, 42);
Memory.writeU32(addr, 0xdeadbeef);
Memory.writePointer(addr, ptr('0x5678'));
Memory.writeUtf8String(addr, 'hello');
```

**After (Frida 17):**
```typescript
const addr = ptr('0x1234');
addr.writeU8(42);
addr.writeU32(0xdeadbeef);
addr.writePointer(ptr('0x5678'));
addr.writeUtf8String('hello');
```

### Chaining Support

The new API supports method chaining:

```typescript
const data = ptr('0x1234');
data
  .add(4).writeU32(13)
  .add(4).writeU16(37)
  .add(2).writeU16(42);
```

---

## Optimization Strategy

### Single Module Variable

When multiple calls reference the same module, Diciassette creates a single variable and reuses it:

**Before:**
```typescript
const fn1 = Module.getExportByName('libc.so', 'open');
const fn2 = Module.getExportByName('libc.so', 'close');
const fn3 = Module.getExportByName('libc.so', 'read');
const fn4 = Module.getExportByName('libc.so', 'write');
const base = Module.getBaseAddress('libc.so');
const sym = Module.getSymbolByName('libc.so', 'malloc');
```

**After (Optimized):**
```typescript
const libc_so = Process.getModuleByName('libc.so');
const fn1 = libc_so.getExportByName('open');
const fn2 = libc_so.getExportByName('close');
const fn3 = libc_so.getExportByName('read');
const fn4 = libc_so.getExportByName('write');
const base = libc_so.base;
const sym = libc_so.getSymbolByName('malloc');
```

### Variable Naming

Module names are converted to valid JavaScript identifiers:

- `libc.so` → `libc_so`
- `libsystem_kernel.dylib` → `libsystem_kernel_dylib`
- `Foundation` → `Foundation`

### Collision Avoidance

If a variable name already exists, a suffix is added:

```typescript
const libsystem_kernel_dylib = "existing variable";
// Transpiler will use: libsystem_kernel_dylib_1
```

### Performance Benefits

**Before (6 Module lookups):**
```typescript
const fn1 = Module.getExportByName('libc.so', 'fn1'); // lookup 1
const fn2 = Module.getExportByName('libc.so', 'fn2'); // lookup 2
const fn3 = Module.getExportByName('libc.so', 'fn3'); // lookup 3
const fn4 = Module.getExportByName('libc.so', 'fn4'); // lookup 4
const fn5 = Module.getExportByName('libc.so', 'fn5'); // lookup 5
const fn6 = Module.getExportByName('libc.so', 'fn6'); // lookup 6
```

**After (1 Module lookup + 6 export lookups):**
```typescript
const libc_so = Process.getModuleByName('libc.so'); // lookup 1
const fn1 = libc_so.getExportByName('fn1');
const fn2 = libc_so.getExportByName('fn2');
const fn3 = libc_so.getExportByName('fn3');
const fn4 = libc_so.getExportByName('fn4');
const fn5 = libc_so.getExportByName('fn5');
const fn6 = libc_so.getExportByName('fn6');
```

---

## What Is NOT Transformed

The following patterns are preserved as-is:

### Already-Modern API
```typescript
// These are already Frida 17 style
const mod = Process.getModuleByName('libc.so');
const fn = mod.getExportByName('open');
const value = ptr('0x1234').readU32();
```

### Dynamic Module Names
```typescript
// Variables are left as-is for safety
const moduleName = getModuleName();
const fn = Module.getExportByName(moduleName, 'open'); // Not transformed
```

### Other Module APIs
```typescript
// Different APIs that don't need transformation
Module.load('/path/to/lib.so');
Module.getGlobalExportByName('exit');
```

---

## Complete Example

### Before (Frida 16)
```typescript
// Multiple module lookups
const open = Module.getExportByName('libc.so.6', 'open');
const close = Module.getExportByName('libc.so.6', 'close');
const base = Module.getBaseAddress('libc.so.6');

Module.ensureInitialized('Foundation');

// Old memory API
const health = Memory.readU32(ptr('0x1000'));
Memory.writeU32(ptr('0x1000'), 100);
```

### After (Frida 17)
```typescript
// Single module lookup + reuse
const libc_so_6 = Process.getModuleByName('libc.so.6');
const open = libc_so_6.getExportByName('open');
const close = libc_so_6.getExportByName('close');
const base = libc_so_6.base;

Process.getModuleByName('Foundation').ensureInitialized();

// New memory API
const health = ptr('0x1000').readU32();
ptr('0x1000').writeU32(100);
```
