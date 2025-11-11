// Frida 16 style - this will be transformed to Frida 17 style

// Hook some libc functions
const openPtr = Module.getExportByName('libc.so.6', 'open');
const closePtr = Module.getExportByName('libc.so.6', 'close');
const readPtr = Module.getExportByName('libc.so.6', 'read');
const writePtr = Module.getExportByName('libc.so.6', 'write');

// Attach interceptors
Interceptor.attach(openPtr, {
  onEnter(args) {
    const path = args[0].readUtf8String();
    console.log(`open("${path}")`);
  }
});

Interceptor.attach(Module.getExportByName('libc.so.6', 'close'), {
  onEnter(args) {
    console.log(`close(${args[0]})`);
  }
});

// Hook malloc/free
const mallocPtr = Module.getExportByName('libc.so.6', 'malloc');
const freePtr = Module.getExportByName('libc.so.6', 'free');

Interceptor.attach(mallocPtr, {
  onEnter(args) {
    console.log(`malloc(${args[0]})`);
  },
  onLeave(retval) {
    console.log(`  -> ${retval}`);
  }
});

// Hook some pthread functions
const pthreadCreate = Module.getExportByName('libpthread.so.0', 'pthread_create');
const pthreadJoin = Module.findExportByName('libpthread.so.0', 'pthread_join');

console.log('Hooks installed!');
