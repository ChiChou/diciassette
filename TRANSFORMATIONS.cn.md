# Frida 16 → 17 API 转换

本文档详细说明了 Diciassette 执行的所有 API 转换。

## 目录

1. [模块导出/导入 API](#模块导出导入-api)
2. [模块基地址 API](#模块基地址-api)
3. [模块初始化 API](#模块初始化-api)
4. [模块符号 API](#模块符号-api)
5. [内存读写 API](#内存读写-api)
6. [桥接导入](#桥接导入)
7. [优化策略](#优化策略)

---

## 模块导出/导入 API

### `Module.getExportByName(moduleName, exportName)`

**之前 (Frida 16):**
```typescript
const open = Module.getExportByName('libc.so', 'open');
const close = Module.getExportByName('libc.so', 'close');
```

**之后 (Frida 17):**
```typescript
const libc_so = Process.getModuleByName('libc.so');
const open = libc_so.getExportByName('open');
const close = libc_so.getExportByName('close');
```

### `Module.findExportByName(moduleName, exportName)`

**之前 (Frida 16):**
```typescript
const fn = Module.findExportByName('libm.so', 'sin');
```

**之后 (Frida 17):**
```typescript
const libm_so = Process.getModuleByName('libm.so');
const fn = libm_so.findExportByName('sin');
```

### `Module.getExportByName(null, exportName)` - 全局导出

**之前 (Frida 16):**
```typescript
const exit = Module.getExportByName(null, 'exit');
```

**之后 (Frida 17):**
```typescript
const exit = Module.getGlobalExportByName('exit');
```

---

## 模块基地址 API

### `Module.getBaseAddress(moduleName)`

**之前 (Frida 16):**
```typescript
const base = Module.getBaseAddress('libc.so');
const offset = 0x1234;
const addr = base.add(offset);
```

**之后 (Frida 17):**
```typescript
const base = Process.getModuleByName('libc.so').base;
const offset = 0x1234;
const addr = base.add(offset);
```

### `Module.findBaseAddress(moduleName)`

**之前 (Frida 16):**
```typescript
const base = Module.findBaseAddress('libm.so');
```

**之后 (Frida 17):**
```typescript
const base = Process.getModuleByName('libm.so').base;
```

---

## 模块初始化 API

### `Module.ensureInitialized(moduleName)`

**之前 (Frida 16):**
```typescript
Module.ensureInitialized('Foundation');
Module.ensureInitialized('UIKit');
```

**之后 (Frida 17):**
```typescript
Process.getModuleByName('Foundation').ensureInitialized();
Process.getModuleByName('UIKit').ensureInitialized();
```

---

## 模块符号 API

### `Module.getSymbolByName(moduleName, symbolName)`

**之前 (Frida 16):**
```typescript
const sym = Module.getSymbolByName('libc.so', 'open');
```

**之后 (Frida 17):**
```typescript
const sym = Process.getModuleByName('libc.so').getSymbolByName('open');
```

### `Module.findSymbolByName(moduleName, symbolName)`

**之前 (Frida 16):**
```typescript
const sym = Module.findSymbolByName('libc.so', 'close');
```

**之后 (Frida 17):**
```typescript
const sym = Process.getModuleByName('libc.so').findSymbolByName('close');
```

---

## 内存读写 API

### 内存读取 API

所有 `Memory.read*()` 方法都转换为 `ptr.read*()`:

**之前 (Frida 16):**
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

**之后 (Frida 17):**
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

### 内存写入 API

所有 `Memory.write*()` 方法都转换为 `ptr.write*()`:

**之前 (Frida 16):**
```typescript
const addr = ptr('0x1234');
Memory.writeU8(addr, 42);
Memory.writeU32(addr, 0xdeadbeef);
Memory.writePointer(addr, ptr('0x5678'));
Memory.writeUtf8String(addr, 'hello');
```

**之后 (Frida 17):**
```typescript
const addr = ptr('0x1234');
addr.writeU8(42);
addr.writeU32(0xdeadbeef);
addr.writePointer(ptr('0x5678'));
addr.writeUtf8String('hello');
```

### 链式调用支持

新 API 支持方法链式调用:

```typescript
const data = ptr('0x1234');
data
  .add(4).writeU32(13)
  .add(4).writeU16(37)
  .add(2).writeU16(42);
```

---

## 桥接导入

### 自动 ObjC 和 Java 导入检测

在 Frida 17 中,`ObjC` 和 `Java` 对象必须从各自的桥接模块显式导入。Diciassette 自动检测这些对象的使用并在文件顶部添加必要的导入。

### ObjC 桥接导入

**之前 (Frida 16):**
```typescript
const NSString = ObjC.classes.NSString;
const str = NSString.stringWithString_("Hello");
```

**之后 (Frida 17):**
```typescript
import ObjC from "frida-objc-bridge";

const NSString = ObjC.classes.NSString;
const str = NSString.stringWithString_("Hello");
```

### Java 桥接导入

**之前 (Frida 16):**
```typescript
Java.perform(() => {
  const MainActivity = Java.use("com.example.MainActivity");
  MainActivity.onCreate.implementation = function() {
    console.log("onCreate called");
  };
});
```

**之后 (Frida 17):**
```typescript
import Java from "frida-java-bridge";

Java.perform(() => {
  const MainActivity = Java.use("com.example.MainActivity");
  MainActivity.onCreate.implementation = function() {
    console.log("onCreate called");
  };
});
```

### 组合示例

**之前 (Frida 16):**
```typescript
// 不需要导入
const activity = ObjC.classes.UIApplication.sharedApplication();

Java.perform(() => {
  const String = Java.use("java.lang.String");
});
```

**之后 (Frida 17):**
```typescript
import Java from "frida-java-bridge";
import ObjC from "frida-objc-bridge";

const activity = ObjC.classes.UIApplication.sharedApplication();

Java.perform(() => {
  const String = Java.use("java.lang.String");
});
```

### 导入位置

- 导入添加在文件的最开始
- 如果文件已有现有导入,桥接导入会插入在它们之后
- 自动避免重复导入 - 如果导入已存在,则不会再次添加
- 仅在代码中实际使用相应对象(`ObjC` 或 `Java`)时才添加导入

---

## 优化策略

### 单个模块变量

当多个调用引用同一模块时,Diciassette 创建单个变量并重用它:

**之前:**
```typescript
const fn1 = Module.getExportByName('libc.so', 'open');
const fn2 = Module.getExportByName('libc.so', 'close');
const fn3 = Module.getExportByName('libc.so', 'read');
const fn4 = Module.getExportByName('libc.so', 'write');
const base = Module.getBaseAddress('libc.so');
const sym = Module.getSymbolByName('libc.so', 'malloc');
```

**之后(优化):**
```typescript
const libc_so = Process.getModuleByName('libc.so');
const fn1 = libc_so.getExportByName('open');
const fn2 = libc_so.getExportByName('close');
const fn3 = libc_so.getExportByName('read');
const fn4 = libc_so.getExportByName('write');
const base = libc_so.base;
const sym = libc_so.getSymbolByName('malloc');
```

### 变量命名

模块名称转换为有效的 JavaScript 标识符:

- `libc.so` → `libc_so`
- `libsystem_kernel.dylib` → `libsystem_kernel_dylib`
- `Foundation` → `Foundation`

### 冲突避免

如果变量名已存在,会添加后缀:

```typescript
const libsystem_kernel_dylib = "existing variable";
// 转换器将使用: libsystem_kernel_dylib_1
```

### 性能优势

**之前(6 次模块查找):**
```typescript
const fn1 = Module.getExportByName('libc.so', 'fn1'); // 查找 1
const fn2 = Module.getExportByName('libc.so', 'fn2'); // 查找 2
const fn3 = Module.getExportByName('libc.so', 'fn3'); // 查找 3
const fn4 = Module.getExportByName('libc.so', 'fn4'); // 查找 4
const fn5 = Module.getExportByName('libc.so', 'fn5'); // 查找 5
const fn6 = Module.getExportByName('libc.so', 'fn6'); // 查找 6
```

**之后(1 次模块查找 + 6 次导出查找):**
```typescript
const libc_so = Process.getModuleByName('libc.so'); // 查找 1
const fn1 = libc_so.getExportByName('fn1');
const fn2 = libc_so.getExportByName('fn2');
const fn3 = libc_so.getExportByName('fn3');
const fn4 = libc_so.getExportByName('fn4');
const fn5 = libc_so.getExportByName('fn5');
const fn6 = libc_so.getExportByName('fn6');
```

---

## 不转换的内容

以下模式保持原样:

### 已是现代 API
```typescript
// 这些已经是 Frida 17 风格
const mod = Process.getModuleByName('libc.so');
const fn = mod.getExportByName('open');
const value = ptr('0x1234').readU32();
```

### 动态模块名
```typescript
// 为安全起见,变量保持原样
const moduleName = getModuleName();
const fn = Module.getExportByName(moduleName, 'open'); // 不转换
```

### 其他模块 API
```typescript
// 不需要转换的不同 API
Module.load('/path/to/lib.so');
Module.getGlobalExportByName('exit');
```

---

## 完整示例

### 之前 (Frida 16)
```typescript
// 多次模块查找
const open = Module.getExportByName('libc.so.6', 'open');
const close = Module.getExportByName('libc.so.6', 'close');
const base = Module.getBaseAddress('libc.so.6');

Module.ensureInitialized('Foundation');

// 旧内存 API
const health = Memory.readU32(ptr('0x1000'));
Memory.writeU32(ptr('0x1000'), 100);
```

### 之后 (Frida 17)
```typescript
// 单次模块查找 + 重用
const libc_so_6 = Process.getModuleByName('libc.so.6');
const open = libc_so_6.getExportByName('open');
const close = libc_so_6.getExportByName('close');
const base = libc_so_6.base;

Process.getModuleByName('Foundation').ensureInitialized();

// 新内存 API
const health = ptr('0x1000').readU32();
ptr('0x1000').writeU32(100);
```
