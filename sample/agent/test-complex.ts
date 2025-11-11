// Test file using Frida 16 API - complex cases

// Case 1: Multiple modules used multiple times
const libc_open = Module.getExportByName("libc.so", "open");
const libc_read = Module.getExportByName("libc.so", "read");
const libc_write = Module.getExportByName("libc.so", "write");
const libc_close = Module.getExportByName("libc.so", "close");

const libm_sin = Module.getExportByName("libm.so", "sin");
const libm_cos = Module.getExportByName("libm.so", "cos");

const libc_malloc = Module.getExportByName("libc.so", "malloc");
const libc_free = Module.getExportByName("libc.so", "free");

// Case 2: Module names with special characters
const kernel_mach = Module.getExportByName(
  "libsystem_kernel.dylib",
  "mach_absolute_time",
);
const Foundation_NSLog = Module.getExportByName("Foundation", "NSLog");

// Case 3: findExportByName mixed with getExportByName
const libpthread_create = Module.findExportByName(
  "libpthread.so",
  "pthread_create",
);
const libpthread_join = Module.getExportByName("libpthread.so", "pthread_join");
const libpthread_detach = Module.findExportByName(
  "libpthread.so",
  "pthread_detach",
);

// Case 4: In conditionals
function hookIfExists() {
  const addr = Module.getExportByName("libc.so", "some_function");
  if (addr !== null) {
    Interceptor.attach(addr, {
      onEnter(args) {
        console.log("hooked");
      },
    });
  }
}

// Case 5: In arrays and objects
const hooks = [
  Module.getExportByName("libc.so", "fork"),
  Module.getExportByName("libc.so", "execve"),
  Module.getExportByName("libc.so", "system"),
];

const _exports = {
  open: Module.getExportByName("libc.so", "open"),
  close: Module.getExportByName("libc.so", "close"),
};

// Case 6: Chained method calls
const result = Module.getExportByName("libc.so", "strlen").readPointer().add(8);

// Case 7: String literals with various quote styles
const fn1 = Module.getExportByName("libc.so", "func1");
const fn2 = Module.getExportByName("libc.so", "func2");
const fn3 = Module.getExportByName(`libc.so`, `func3`);

// Case 8: Module.getExportByName with dynamic strings (should still work)
const moduleName = "libc.so";
const exportName = "getpid";
const dynamicExport = Module.getExportByName(moduleName, exportName);
