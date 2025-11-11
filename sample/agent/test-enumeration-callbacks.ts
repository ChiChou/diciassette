// Test file for legacy enumeration API transformations (Frida 16 → 17)

// Case 1: Process.enumerateModules with callbacks → array return
Process.enumerateModules({
  onMatch(module) {
    console.log(module.name);
    return 'continue';
  },
  onComplete() {
    console.log('done');
  }
});

// Case 2: Process.enumerateThreads with callbacks
Process.enumerateThreads({
  onMatch(thread) {
    console.log(thread.id);
  },
  onComplete() {
    console.log('done');
  }
});

// Case 3: Process.enumerateRanges with callbacks
Process.enumerateRanges('r--', {
  onMatch(range) {
    console.log(range.base);
  },
  onComplete() {}
});

// Case 4: Module instance enumeration (these should stay as-is in modern API)
const libc = Process.getModuleByName('libc.so');
libc.enumerateExports().forEach(exp => {
  console.log(exp.name);
});

// Case 5: Already modern style - should not change
for (const module of Process.enumerateModules()) {
  console.log(module.name);
}

const threads = Process.enumerateThreads();
threads.forEach(t => console.log(t.id));
