// Comprehensive Frida 16 → 17 transformation demo

// ============================================================================
// 1. Module.getExportByName / findExportByName transformations
// ============================================================================

// Multiple calls to the same module get optimized
const openPtr = Module.getExportByName('libc.so.6', 'open');
const closePtr = Module.getExportByName('libc.so.6', 'close');
const readPtr = Module.getExportByName('libc.so.6', 'read');
const writePtr = Module.getExportByName('libc.so.6', 'write');

// Null module becomes getGlobalExportByName
const exitPtr = Module.getExportByName(null, 'exit');

// ============================================================================
// 2. Module.getBaseAddress / findBaseAddress transformations
// ============================================================================

const libcBase = Module.getBaseAddress('libc.so.6');
const libmBase = Module.findBaseAddress('libm.so.6');

// Use base address in expressions
Interceptor.attach(Module.getBaseAddress('game.so').add(0x1234), {
  onEnter() {
    console.log('Game function called');
  }
});

// ============================================================================
// 3. Module.ensureInitialized transformations
// ============================================================================

Module.ensureInitialized('Foundation');
Module.ensureInitialized('UIKit');

// ============================================================================
// 4. Module.getSymbolByName / findSymbolByName transformations
// ============================================================================

const openSym = Module.getSymbolByName('libc.so.6', 'open');
const closeSym = Module.findSymbolByName('libc.so.6', 'close');

// ============================================================================
// 5. Memory.read* / Memory.write* transformations
// ============================================================================

const playerHealthAddr = ptr('0x12345678');

// Old style Memory API
const health = Memory.readU32(playerHealthAddr);
const mana = Memory.readU16(playerHealthAddr.add(4));
const level = Memory.readU8(playerHealthAddr.add(6));

// Write with old style
Memory.writeU32(playerHealthAddr, 100);
Memory.writeU16(playerHealthAddr.add(4), 50);
Memory.writeU8(playerHealthAddr.add(6), 10);

// Read pointer and string
const namePtr = Memory.readPointer(playerHealthAddr.add(0x10));
const name = Memory.readUtf8String(namePtr);

// Complex expressions
const value1 = Memory.readU32(ptr('0x1000').add(8));
Memory.writeU32(ptr('0x2000').sub(4), 42);

// ============================================================================
// 6. Demonstration of optimization
// ============================================================================

// All these libc.so.6 calls will use a single Process.getModuleByName('libc.so.6')
const malloc = Module.getExportByName('libc.so.6', 'malloc');
const free = Module.getExportByName('libc.so.6', 'free');
const memcpy = Module.getExportByName('libc.so.6', 'memcpy');
const strlen = Module.findExportByName('libc.so.6', 'strlen');

console.log('All transformations complete!');
