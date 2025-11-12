# Diciassette

![AI Slop: YES](badge.svg)

[中文文档](README.cn.md)

**Disclaimer: This whole experimental project is AI generated. I do not take any responsibility for data lose or bug generated**

Upgrade your Frida 16 projects to Frida 17 by transforming obsolete API calls.

https://frida.re/news/2025/05/17/frida-17-0-0-released/

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

For a comprehensive list of all API transformations, see [TRANSFORMATIONS.md](TRANSFORMATIONS.md).

Key transformations include:
- Module export/import APIs (`Module.getExportByName` → `Process.getModuleByName().getExportByName`)
- Module base address APIs (`Module.getBaseAddress` → `Process.getModuleByName().base`)
- Module initialization APIs (`Module.ensureInitialized`)
- Memory read/write APIs (`Memory.readU32(ptr)` → `ptr.readU32()`)
- Automatic ObjC/Java bridge imports for Frida 17

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

## Installation

### Download Pre-built Binaries

Pre-built binaries for macOS (x64/ARM64), Linux (x64), and Windows (x64) are available on the [GitHub Releases page](https://github.com/frida/diciassette/releases).

Simply download the appropriate binary for your platform and run it directly.

### Building from Source

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
