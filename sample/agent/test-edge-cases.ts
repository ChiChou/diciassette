// Test file using Frida 16 API - edge cases

// Case 1: Nested in complex expressions
const addr1 = ptr(Module.getExportByName('libc.so', 'printf')).add(16);

// Case 2: As function arguments
function attachHook(address: NativePointer) {
  Interceptor.attach(address, {
    onEnter(args) {
      console.log('called');
    }
  });
}

attachHook(Module.getExportByName('libc.so', 'strlen'));
attachHook(Module.getExportByName('libm.so', 'sqrt'));

// Case 3: In ternary expressions
const hook = someCondition
  ? Module.getExportByName('libc.so', 'func_a')
  : Module.getExportByName('libc.so', 'func_b');

// Case 4: In arrow functions
const getFunctionAddress = (name: string) => Module.getExportByName('libc.so', name);

// Case 5: Immediately invoked
new NativeFunction(
  Module.getExportByName('libc.so', 'getpid'),
  'int',
  []
)();

// Case 6: Multiple in same statement
const [a, b, c] = [
  Module.getExportByName('libc.so', 'a'),
  Module.getExportByName('libc.so', 'b'),
  Module.getExportByName('libc.so', 'c')
];

// Case 7: With method chaining after
const value = Module.getExportByName('libc.so', 'errno_ptr')
  .readPointer()
  .readInt();

// Case 8: Single occurrence (should not create unnecessary variable)
const singleUse = Module.getExportByName('unique_lib.so', 'unique_export');

// Case 9: Variable name collision avoidance
const libsystem_kernel_dylib = "existing variable";
const more = Module.getExportByName('libsystem_kernel.dylib', 'more');

// Case 10: Scoped declarations
{
  const scoped1 = Module.getExportByName('lib1.so', 'func1');
  const scoped2 = Module.getExportByName('lib1.so', 'func2');
}

{
  const scoped3 = Module.getExportByName('lib1.so', 'func3');
  const scoped4 = Module.getExportByName('lib1.so', 'func4');
}

// Declare someCondition
declare const someCondition: boolean;
