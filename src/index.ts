#!/usr/bin/env bun

import { FridaTranspiler } from "./transpiler";
import * as path from "path";
import * as fs from "fs";

interface TransformOptions {
  input: string;
  output?: string;
  inPlace?: boolean;
  dryRun?: boolean;
}

/**
 * Transform a single file or directory
 */
async function transformPath(options: TransformOptions): Promise<void> {
  const transpiler = new FridaTranspiler();
  const inputPath = path.resolve(options.input);

  // Check if input exists
  if (!fs.existsSync(inputPath)) {
    console.error(`Error: Input path does not exist: ${inputPath}`);
    process.exit(1);
  }

  const stats = fs.statSync(inputPath);

  if (stats.isFile()) {
    // Transform single file
    await transformFile(transpiler, inputPath, options);
  } else if (stats.isDirectory()) {
    // Transform directory
    await transformDirectory(transpiler, inputPath, options);
  } else {
    console.error(
      `Error: Input path is neither a file nor a directory: ${inputPath}`,
    );
    process.exit(1);
  }
}

/**
 * Transform a single file
 */
async function transformFile(
  transpiler: FridaTranspiler,
  filePath: string,
  options: TransformOptions,
): Promise<void> {
  console.log(`Transforming: ${filePath}`);

  const sourceFile = transpiler.addSourceFile(filePath);
  transpiler.transformFile(sourceFile);

  const transformedText = transpiler.getTransformedText(sourceFile);

  if (options.dryRun) {
    console.log("\n--- Transformed output (dry run) ---\n");
    console.log(transformedText);
    console.log("\n--- End of output ---\n");
  } else if (options.inPlace) {
    // Overwrite original file
    fs.writeFileSync(filePath, transformedText, "utf-8");
    console.log(`✓ Updated: ${filePath}`);
  } else if (options.output) {
    // Write to output file
    const outputPath = path.resolve(options.output);
    fs.mkdirSync(path.dirname(outputPath), { recursive: true });
    fs.writeFileSync(outputPath, transformedText, "utf-8");
    console.log(`✓ Created: ${outputPath}`);
  } else {
    // Print to stdout
    console.log(transformedText);
  }
}

/**
 * Transform all TypeScript files in a directory
 */
async function transformDirectory(
  transpiler: FridaTranspiler,
  dirPath: string,
  options: TransformOptions,
): Promise<void> {
  // Find all .ts files recursively
  const tsFiles = findTypeScriptFiles(dirPath);

  if (tsFiles.length === 0) {
    console.log(`No TypeScript files found in: ${dirPath}`);
    return;
  }

  console.log(`Found ${tsFiles.length} TypeScript file(s) in: ${dirPath}\n`);

  // Add all files to the transpiler
  for (const filePath of tsFiles) {
    transpiler.addSourceFile(filePath);
  }

  // Transform all files
  transpiler.transformAll();

  // Process each file
  for (const filePath of tsFiles) {
    const sourceFile = transpiler.project.getSourceFile(filePath);
    if (!sourceFile) continue;

    const transformedText = transpiler.getTransformedText(sourceFile);

    if (options.dryRun) {
      console.log(`\n--- ${filePath} ---\n`);
      console.log(transformedText);
      console.log(`\n--- End of ${filePath} ---\n`);
    } else if (options.inPlace) {
      fs.writeFileSync(filePath, transformedText, "utf-8");
      console.log(`✓ Updated: ${filePath}`);
    } else if (options.output) {
      // Preserve directory structure
      const relativePath = path.relative(dirPath, filePath);
      const outputPath = path.join(options.output, relativePath);
      fs.mkdirSync(path.dirname(outputPath), { recursive: true });
      fs.writeFileSync(outputPath, transformedText, "utf-8");
      console.log(`✓ Created: ${outputPath}`);
    } else {
      console.log(`\n--- ${filePath} ---\n`);
      console.log(transformedText);
      console.log(`\n--- End of ${filePath} ---\n`);
    }
  }

  console.log(`\n✓ Transformed ${tsFiles.length} file(s)`);
}

/**
 * Find all TypeScript files in a directory recursively
 */
function findTypeScriptFiles(dirPath: string): string[] {
  const files: string[] = [];

  function traverse(currentPath: string): void {
    const entries = fs.readdirSync(currentPath, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = path.join(currentPath, entry.name);

      if (entry.isDirectory()) {
        // Skip node_modules and hidden directories
        if (entry.name === "node_modules" || entry.name.startsWith(".")) {
          continue;
        }
        traverse(fullPath);
      } else if (entry.isFile() && entry.name.endsWith(".ts")) {
        files.push(fullPath);
      }
    }
  }

  traverse(dirPath);
  return files;
}

/**
 * Print usage information
 */
function printUsage(): void {
  console.log(`
Diciassette - Upgrade Frida projects from v16 to v17

Usage:
  diciassette <input> [options]

Arguments:
  <input>              Input file or directory to transform

Options:
  -o, --output <path>  Output file or directory (preserves structure for directories)
  -i, --in-place       Transform files in place (overwrite originals)
  -d, --dry-run        Print transformed output without writing files
  -h, --help           Show this help message

Examples:
  # Transform a single file and print to stdout
  diciassette agent.ts

  # Transform a file and save to a new file
  diciassette agent.ts -o agent-v17.ts

  # Transform a file in place
  diciassette agent.ts -i

  # Transform all files in a directory
  diciassette ./src -o ./src-v17

  # Transform all files in place
  diciassette ./src -i

  # Dry run to see changes without writing
  diciassette ./src -d
`);
}

/**
 * Main entry point
 */
async function main(): Promise<void> {
  const args = process.argv.slice(2);

  if (args.length === 0 || args.includes("-h") || args.includes("--help")) {
    printUsage();
    process.exit(0);
  }

  const options: TransformOptions = {
    input: args[0],
  };

  // Parse options
  for (let i = 1; i < args.length; i++) {
    const arg = args[i];

    if (arg === "-o" || arg === "--output") {
      options.output = args[++i];
    } else if (arg === "-i" || arg === "--in-place") {
      options.inPlace = true;
    } else if (arg === "-d" || arg === "--dry-run") {
      options.dryRun = true;
    } else {
      console.error(`Unknown option: ${arg}`);
      printUsage();
      process.exit(1);
    }
  }

  // Validate options
  if (options.inPlace && options.output) {
    console.error("Error: Cannot use both --in-place and --output");
    process.exit(1);
  }

  try {
    await transformPath(options);
  } catch (error) {
    console.error("Error:", error);
    process.exit(1);
  }
}

// Run the CLI
main();
