// Test file using Frida 16 API - basic cases

// Case 1: Simple Module.getExportByName calls with same module
const open = Module.getExportByName('libsystem_kernel.dylib', 'open');
const close = Module.getExportByName('libsystem_kernel.dylib', 'close');
const read = Module.getExportByName('libsystem_kernel.dylib', 'read');

// Case 2: Module.getExportByName calls with different modules
const malloc = Module.getExportByName('libsystem_malloc.dylib', 'malloc');
const free = Module.getExportByName('libsystem_malloc.dylib', 'free');
const pthread_create = Module.getExportByName('libsystem_pthread.dylib', 'pthread_create');

// Case 3: Module.findExportByName (should also be transformed)
const write = Module.findExportByName('libsystem_kernel.dylib', 'write');
const stat = Module.findExportByName('libsystem_kernel.dylib', 'stat');

// Case 4: Module.getExportByName used directly in Interceptor.attach
Interceptor.attach(Module.getExportByName('libsystem_kernel.dylib', 'connect'), {
  onEnter(args) {
    console.log('connect called');
  }
});

// Case 5: Module.getExportByName in expressions
const openPtr = new NativeFunction(
  Module.getExportByName('libsystem_kernel.dylib', 'open'),
  'int',
  ['pointer', 'int']
);

// Case 6: Module.getExportByName with null module (should become Module.getGlobalExportByName)
const someGlobal = Module.getExportByName(null, 'exit');

// Case 7: Should NOT be transformed - already correct API
const mod = Process.getModuleByName('libsystem_kernel.dylib');
const dup = mod.getExportByName('dup');

// Case 8: Should NOT be transformed - Module.load
const loadedMod = Module.load('/usr/lib/libz.dylib');
