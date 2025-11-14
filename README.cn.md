# Diciassette

![AI Slop: YES](badge.svg)

**免责声明:整个实验项目由 AI 生成。我不对数据丢失或生成的 bug 承担任何责任**

通过转换过时的 API 调用,将您的 Frida 16 项目升级到 Frida 17。

https://frida.re/news/2025/05/17/frida-17-0-0-released/

## 命令行用法

### 基本命令

```bash
# 转换单个文件并打印到标准输出
diciassette agent.ts

# 将转换后的输出保存到新文件
diciassette agent.ts -o agent-v17.ts

# 原地转换文件(覆盖原文件)
diciassette agent.ts -i

# 转换目录中的所有 TypeScript 文件
diciassette ./src -o ./src-v17

# 原地转换目录
diciassette ./src -i

# 试运行(查看更改但不写入文件)
diciassette ./src -d
```

### 选项

- `-o, --output <path>` - 输出文件或目录
- `-i, --in-place` - 原地转换文件(覆盖原文件)
- `-d, --dry-run` - 预览更改但不写入文件
- `-h, --help` - 显示帮助信息

## 转换内容

有关所有 API 转换的完整列表,请参阅 [TRANSFORMATIONS.cn.md](TRANSFORMATIONS.cn.md)。

主要转换包括:
- 模块导出/导入 API (`Module.getExportByName` → `Process.getModuleByName().getExportByName`)
- 模块基地址 API (`Module.getBaseAddress` → `Process.getModuleByName().base`)
- 模块初始化 API (`Module.ensureInitialized`)
- 内存读写 API (`Memory.readU32(ptr)` → `ptr.readU32()`)
- 为 Frida 17 自动添加 ObjC/Java 桥接导入

## 示例

给定 `sample/agent/demo.ts`:

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

运行 `diciassette sample/agent/demo.ts -o demo-v17.ts` 生成:

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

## 安装

### 下载预编译二进制文件

可在 [GitHub Releases 页面](https://github.com/chichou/diciassette/releases) 获取适用于 macOS (x64/ARM64)、Linux (x64) 和 Windows (x64) 的预编译二进制文件。

只需下载适合您平台的二进制文件并直接运行即可。

### 从源代码构建

```bash
# 安装依赖
bun install

# 构建可执行文件
bun run build

# 编译后的二进制文件位于 dist/diciassette
./dist/diciassette --help
```

## 开发

```bash
# 以开发模式运行
bun run dev sample/agent/demo.ts -d

# 在示例文件上测试
bun run dev sample/agent -d
```
