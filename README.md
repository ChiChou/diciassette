# Diciassette

**Disclaimer: This whole experimental project is AI generated. I do not take any responsibility for data lose or bug generated**

Upgrade your Frida 16 projects to Frida 17 by transforming obsolete API calls.

## What it does

### Main Transformation

Converts the deprecated `Module.getExportByName(moduleName, exportName)` pattern to the new Frida 17 API:

**Before (Frida 16):**
```typescript
const open = Module.getExportByName('libc.so', 'open');
const close = Module.getExportByName('libc.so', 'close');
const read = Module.getExportByName('libc.so', 'read');
```

**After (Frida 17):**
```typescript
const libc_so = Process.getModuleByName('libc.so');
const open = libc_so.getExportByName('open');
const close = libc_so.getExportByName('close');
const read = libc_so.getExportByName('read');
```

### Optimization

The tool intelligently groups calls by module name and creates a single variable per module, avoiding redundant `Process.getModuleByName()` calls:

```typescript
// Instead of:
const fn1 = Process.getModuleByName('libc.so').getExportByName('fn1');
const fn2 = Process.getModuleByName('libc.so').getExportByName('fn2');
const fn3 = Process.getModuleByName('libc.so').getExportByName('fn3');

// It generates:
const libc_so = Process.getModuleByName('libc.so');
const fn1 = libc_so.getExportByName('fn1');
const fn2 = libc_so.getExportByName('fn2');
const fn3 = libc_so.getExportByName('fn3');
```

### Null Module Handling

Converts null module names to the appropriate global export function:

**Before:**
```typescript
const exit = Module.getExportByName(null, 'exit');
```

**After:**
```typescript
const exit = Module.getGlobalExportByName('exit');
```

## Command Line Usage

### Basic Commands

```bash
# Transform a single file and print to stdout
diciassette agent.ts

# Save transformed output to a new file
diciassette agent.ts -o agent-v17.ts

# Transform a file in place (overwrites original)
diciassette agent.ts -i

# Transform all TypeScript files in a directory
diciassette ./src -o ./src-v17

# Transform directory in place
diciassette ./src -i

# Dry run (see changes without writing files)
diciassette ./src -d
```

### Options

- `-o, --output <path>` - Output file or directory
- `-i, --in-place` - Transform files in place (overwrites originals)
- `-d, --dry-run` - Preview changes without writing files
- `-h, --help` - Show help message

## What Gets Transformed

### ✅ Module Export/Import APIs
- `Module.getExportByName(moduleName, exportName)` → `Process.getModuleByName(moduleName).getExportByName(exportName)`
- `Module.findExportByName(moduleName, exportName)` → `Process.getModuleByName(moduleName).findExportByName(exportName)`
- `Module.getExportByName(null, exportName)` → `Module.getGlobalExportByName(exportName)`
- `Module.getSymbolByName(moduleName, symbolName)` → `Process.getModuleByName(moduleName).getSymbolByName(symbolName)`
- `Module.findSymbolByName(moduleName, symbolName)` → `Process.getModuleByName(moduleName).findSymbolByName(symbolName)`

### ✅ Module Base Address APIs
- `Module.getBaseAddress(moduleName)` → `Process.getModuleByName(moduleName).base`
- `Module.findBaseAddress(moduleName)` → `Process.getModuleByName(moduleName).base`

### ✅ Module Initialization APIs
- `Module.ensureInitialized(moduleName)` → `Process.getModuleByName(moduleName).ensureInitialized()`

### ✅ Memory Read/Write APIs
- `Memory.readU8(ptr)` → `ptr.readU8()`
- `Memory.readU16(ptr)` → `ptr.readU16()`
- `Memory.readU32(ptr)` → `ptr.readU32()`
- `Memory.readU64(ptr)` → `ptr.readU64()`
- `Memory.readS8(ptr)` / `readS16()` / `readS32()` / `readS64()` → `ptr.readS*()`
- `Memory.readFloat(ptr)` / `readDouble()` → `ptr.readFloat()` / `ptr.readDouble()`
- `Memory.readPointer(ptr)` → `ptr.readPointer()`
- `Memory.readByteArray(ptr, length)` → `ptr.readByteArray(length)`
- `Memory.readUtf8String(ptr)` / `readUtf16String()` / etc. → `ptr.readUtf8String()` / etc.
- `Memory.writeU8(ptr, value)` → `ptr.writeU8(value)`
- All other `Memory.write*()` → `ptr.write*()`

### ✅ Preserved (no changes)
- `Process.getModuleByName()` - already correct API
- `module.getExportByName()` - instance method calls
- `Module.load()` - different API
- `Module.getGlobalExportByName()` - already correct
- `ptr.readU32()` / `ptr.writeU32()` - already correct
- Dynamic module names (variables) - left as-is for safety
- Legacy enumeration APIs with callbacks - still supported in Frida 17

## Example

Given `sample/agent/demo.ts`:

```typescript
const openPtr = Module.getExportByName('libc.so.6', 'open');
const closePtr = Module.getExportByName('libc.so.6', 'close');
const readPtr = Module.getExportByName('libc.so.6', 'read');

Interceptor.attach(openPtr, {
  onEnter(args) {
    console.log(`open("${args[0].readUtf8String()}")`);
  }
});
```

Running `diciassette sample/agent/demo.ts -o demo-v17.ts` produces:

```typescript
const libc_so_6 = Process.getModuleByName('libc.so.6');
const openPtr = libc_so_6.getExportByName('open');
const closePtr = libc_so_6.getExportByName('close');
const readPtr = libc_so_6.getExportByName('read');

Interceptor.attach(openPtr, {
  onEnter(args) {
    console.log(`open("${args[0].readUtf8String()}")`);
  }
});
```

## Building from Source

```bash
# Install dependencies
bun install

# Build the executable
bun run build

# The compiled binary will be at dist/diciassette
./dist/diciassette --help
```

## Development

```bash
# Run in development mode
bun run dev sample/agent/demo.ts -d

# Test on sample files
bun run dev sample/agent -d
```
