// Test file for Memory API transformations (Frida 16 → 17)

// Case 1: Memory.read* → ptr.read*
const addr = ptr('0x1234');
const u8 = Memory.readU8(addr);
const u16 = Memory.readU16(addr);
const u32 = Memory.readU32(addr);
const u64 = Memory.readU64(addr);
const s8 = Memory.readS8(addr);
const s16 = Memory.readS16(addr);
const s32 = Memory.readS32(addr);
const s64 = Memory.readS64(addr);
const float = Memory.readFloat(addr);
const double = Memory.readDouble(addr);
const pointer = Memory.readPointer(addr);
const bytes = Memory.readByteArray(addr, 16);
const utf8 = Memory.readUtf8String(addr);
const utf16 = Memory.readUtf16String(addr);
const ansi = Memory.readAnsiString(addr);
const cstr = Memory.readCString(addr);

// Case 2: Memory.write* → ptr.write*
Memory.writeU8(addr, 42);
Memory.writeU16(addr, 1337);
Memory.writeU32(addr, 0xdeadbeef);
Memory.writeU64(addr, uint64('0x123456789'));
Memory.writeS8(addr, -1);
Memory.writeS16(addr, -100);
Memory.writeS32(addr, -1000);
Memory.writeS64(addr, int64('-12345'));
Memory.writeFloat(addr, 3.14);
Memory.writeDouble(addr, 2.71828);
Memory.writePointer(addr, ptr('0x5678'));
Memory.writeUtf8String(addr, 'hello');
Memory.writeUtf16String(addr, 'world');
Memory.writeAnsiString(addr, 'test');
Memory.writeByteArray(addr, [0x01, 0x02, 0x03]);

// Case 3: Complex expressions
const value = Memory.readU32(ptr('0x1000').add(8));
Memory.writeU32(ptr('0x2000').sub(4), 100);

// Case 4: In function calls
function readHealth(playerPtr: NativePointer) {
  return Memory.readU32(playerPtr.add(0x10));
}

// Case 5: Should still work - already using new API
const newStyleRead = addr.readU32();
addr.writeU32(42);
