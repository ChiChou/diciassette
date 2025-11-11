// Test file for Module static API transformations (Frida 16 → 17)

// Case 1: Module.findBaseAddress / getBaseAddress → Process.getModuleByName().base
const libcBase = Module.getBaseAddress('libc.so');
const libmBase = Module.findBaseAddress('libm.so');

// Case 2: Module.ensureInitialized → Process.getModuleByName().ensureInitialized()
Module.ensureInitialized('Foundation');
Module.ensureInitialized('UIKit');

// Case 3: Module.findSymbolByName / getSymbolByName
const openSym = Module.getSymbolByName('libc.so', 'open');
const closeSym = Module.findSymbolByName('libc.so', 'close');

// Case 4: Complex usage
const baseAddr = Module.getBaseAddress('mylib.so');
const offset = 0x1000;
const funcAddr = baseAddr.add(offset);

// Case 5: In expressions
Interceptor.attach(Module.getBaseAddress('game.so').add(0x12345), {
  onEnter(args) {
    console.log('hooked');
  }
});

// Case 6: Module.enumerateExports (static) - should become instance method
Module.enumerateExports('libc.so', {
  onMatch(exp) {
    console.log(exp.name);
  },
  onComplete() {
    console.log('done');
  }
});

// Case 7: Module.enumerateImports (static)
Module.enumerateImports('myapp', {
  onMatch(imp) {
    console.log(imp.name);
  },
  onComplete() {}
});

// Case 8: Module.enumerateSymbols (static)
Module.enumerateSymbols('libc.so', {
  onMatch(sym) {
    console.log(sym.name);
  },
  onComplete() {}
});
