import {
  Project,
  SourceFile,
  Node,
  SyntaxKind,
  CallExpression,
  Statement,
  // Notes from human. The following 2 lines are not AI generated!
  // do not handle scope issues for now, just blindly add suffixes
  // VariableDeclarationKind,
  // Scope,
} from "ts-morph";

interface ModuleUsage {
  moduleName: string;
  calls: CallExpression[];
  isLiteral: boolean;
}

export class FridaTranspiler {
  public project: Project;

  constructor() {
    this.project = new Project({
      compilerOptions: {
        target: 99, // ESNext
        module: 99, // ESNext
      },
    });
  }

  /**
   * Add a source file to the project
   */
  addSourceFile(filePath: string): SourceFile {
    return this.project.addSourceFileAtPath(filePath);
  }

  /**
   * Create a source file from text
   */
  createSourceFile(fileName: string, sourceText: string): SourceFile {
    return this.project.createSourceFile(fileName, sourceText, {
      overwrite: true,
    });
  }

  /**
   * Transform all files in the project
   */
  transformAll(): void {
    for (const sourceFile of this.project.getSourceFiles()) {
      this.transformFile(sourceFile);
    }
  }

  /**
   * Transform a single source file
   */
  transformFile(sourceFile: SourceFile): void {
    // Transform Module.getExportByName and Module.findExportByName
    const moduleUsages = this.findModuleUsages(sourceFile);
    const usageMap = new Map<string, ModuleUsage>();

    for (const usage of moduleUsages) {
      if (!usageMap.has(usage.moduleName)) {
        usageMap.set(usage.moduleName, {
          moduleName: usage.moduleName,
          calls: [],
          isLiteral: usage.isLiteral,
        });
      }
      usageMap.get(usage.moduleName)!.calls.push(usage.call);
    }

    for (const [moduleName, usage] of usageMap) {
      if (moduleName === "null") {
        this.transformNullModule(usage.calls);
      } else if (usage.isLiteral) {
        this.transformModuleCalls(sourceFile, usage);
      }
    }

    // Transform Memory.read* / Memory.write* → ptr.read* / ptr.write*
    this.transformMemoryAPIs(sourceFile);

    // Transform Module.getBaseAddress / findBaseAddress
    this.transformModuleBaseAddress(sourceFile);

    // Transform Module.ensureInitialized
    this.transformModuleEnsureInitialized(sourceFile);

    // Transform Module.getSymbolByName / findSymbolByName
    this.transformModuleSymbolAPIs(sourceFile);

    // Transform legacy enumeration APIs with callbacks
    this.transformLegacyEnumerationAPIs(sourceFile);

    // Add ObjC and Java imports if needed
    this.addBridgeImports(sourceFile);
  }

  /**
   * Find all Module.getExportByName and Module.findExportByName calls
   */
  private findModuleUsages(sourceFile: SourceFile): Array<{
    moduleName: string;
    exportName: string;
    call: CallExpression;
    methodName: "getExportByName" | "findExportByName";
    isLiteral: boolean;
  }> {
    const usages: Array<{
      moduleName: string;
      exportName: string;
      call: CallExpression;
      methodName: "getExportByName" | "findExportByName";
      isLiteral: boolean;
    }> = [];

    sourceFile.forEachDescendant((node) => {
      if (Node.isCallExpression(node)) {
        const expression = node.getExpression();

        // Check if it's Module.getExportByName or Module.findExportByName
        if (Node.isPropertyAccessExpression(expression)) {
          const object = expression.getExpression();
          const property = expression.getName();

          if (
            Node.isIdentifier(object) &&
            object.getText() === "Module" &&
            (property === "getExportByName" || property === "findExportByName")
          ) {
            const args = node.getArguments();
            if (args.length === 2) {
              const moduleArg = args[0];
              const exportArg = args[1];

              // Get module name
              let moduleName: string;
              let isLiteral = false;

              if (moduleArg.getKind() === SyntaxKind.NullKeyword) {
                moduleName = "null";
                isLiteral = true;
              } else if (
                Node.isStringLiteral(moduleArg) ||
                Node.isNoSubstitutionTemplateLiteral(moduleArg)
              ) {
                moduleName = moduleArg.getLiteralValue() as string;
                isLiteral = true;
              } else {
                // Dynamic module name - use the expression text
                moduleName = moduleArg.getText();
                isLiteral = false;
              }

              // Get export name (for reference, though we'll keep the original arg)
              const exportName =
                Node.isStringLiteral(exportArg) ||
                Node.isNoSubstitutionTemplateLiteral(exportArg)
                  ? (exportArg.getLiteralValue() as string)
                  : exportArg.getText();

              usages.push({
                moduleName,
                exportName,
                call: node,
                methodName: property as "getExportByName" | "findExportByName",
                isLiteral,
              });
            }
          }
        }
      }
    });

    return usages;
  }

  /**
   * Transform Module.getExportByName(null, 'export') to Module.getGlobalExportByName('export')
   */
  private transformNullModule(calls: CallExpression[]): void {
    for (const call of calls) {
      const expression = call.getExpression();
      if (Node.isPropertyAccessExpression(expression)) {
        const methodName = expression.getName();
        const args = call.getArguments();

        if (args.length === 2) {
          const exportArg = args[1];

          // Replace with Module.getGlobalExportByName or Module.findGlobalExportByName
          const newMethodName =
            methodName === "getExportByName"
              ? "getGlobalExportByName"
              : "findGlobalExportByName";

          call.replaceWithText(
            `Module.${newMethodName}(${exportArg.getText()})`,
          );
        }
      }
    }
  }

  /**
   * Transform calls for a specific module
   */
  private transformModuleCalls(
    sourceFile: SourceFile,
    usage: ModuleUsage,
  ): void {
    if (usage.calls.length === 0) return;

    // For literal module names, create a variable and reuse it
    if (usage.isLiteral) {
      // Find the optimal insertion point (before the first usage)
      const firstCall = usage.calls[0];
      const insertionPoint = this.findInsertionPoint(firstCall);

      if (!insertionPoint) return;

      // Generate a unique variable name
      const varName = this.generateVariableName(sourceFile, usage.moduleName);

      // Insert the variable declaration
      // The insertionPoint should be a statement itself
      const statement = insertionPoint;
      let statementParent = statement.getParent();

      // If the parent is null, the statement is likely at the top level of the source file
      if (!statementParent || Node.isSourceFile(statementParent)) {
        statementParent = sourceFile;
      }

      if (!statementParent) return;

      // Find the index to insert before
      let insertIndex = 0;
      if (Node.isSourceFile(statementParent)) {
        insertIndex = statementParent
          .getStatements()
          .indexOf(statement as Statement);
      } else if (Node.isBlock(statementParent)) {
        insertIndex = statementParent
          .getStatements()
          .indexOf(statement as Statement);
      } else if (
        Node.isCaseClause(statementParent) ||
        Node.isDefaultClause(statementParent)
      ) {
        insertIndex = statementParent
          .getStatements()
          .indexOf(statement as Statement);
      } else {
        // For other cases, try to insert at the beginning
        insertIndex = 0;
      }

      // Create the variable declaration
      const varDeclaration = `const ${varName} = Process.getModuleByName(${JSON.stringify(usage.moduleName)});`;

      // Insert the variable declaration
      if (Node.isSourceFile(statementParent)) {
        statementParent.insertStatements(insertIndex, varDeclaration);
      } else if (Node.isBlock(statementParent)) {
        statementParent.insertStatements(insertIndex, varDeclaration);
      } else if (
        Node.isCaseClause(statementParent) ||
        Node.isDefaultClause(statementParent)
      ) {
        statementParent.insertStatements(insertIndex, varDeclaration);
      } else {
        // Fallback: try to insert before the statement
        statement.replaceWithText(`${varDeclaration}\n${statement.getText()}`);
      }

      // Replace all calls with the new syntax
      for (const call of usage.calls) {
        const expression = call.getExpression();
        if (Node.isPropertyAccessExpression(expression)) {
          const methodName = expression.getName();
          const args = call.getArguments();

          if (args.length === 2) {
            const exportArg = args[1];

            // Replace with varName.getExportByName(exportArg)
            call.replaceWithText(
              `${varName}.${methodName}(${exportArg.getText()})`,
            );
          }
        }
      }
    } else {
      // For dynamic module names, inline the transformation without creating a variable
      for (const call of usage.calls) {
        const expression = call.getExpression();
        if (Node.isPropertyAccessExpression(expression)) {
          const methodName = expression.getName();
          const args = call.getArguments();

          if (args.length === 2) {
            const moduleArg = args[0];
            const exportArg = args[1];

            // Transform Module.getExportByName(dynamicExpr, "export")
            // to Process.getModuleByName(dynamicExpr).getExportByName("export")
            call.replaceWithText(
              `Process.getModuleByName(${moduleArg.getText()}).${methodName}(${exportArg.getText()})`,
            );
          }
        }
      }
    }
  }

  /**
   * Find the statement to insert the variable declaration before
   */
  private findInsertionPoint(node: Node): Node | null {
    let current: Node | undefined = node;

    while (current) {
      const parent = current.getParent();

      // If parent is a source file, block, or other statement container
      if (
        parent &&
        (Node.isSourceFile(parent) ||
          Node.isBlock(parent) ||
          Node.isCaseClause(parent) ||
          Node.isDefaultClause(parent))
      ) {
        return current;
      }

      current = parent;
    }

    return null;
  }

  /**
   * Generate a unique variable name for the module
   */
  private generateVariableName(
    sourceFile: SourceFile,
    moduleName: string,
  ): string {
    // Convert module name to a valid identifier
    // e.g., "libsystem_kernel.dylib" -> "libsystem_kernel_dylib"
    let baseName = moduleName
      .replace(/[^a-zA-Z0-9_]/g, "_")
      .replace(/^[0-9]/, "_$&"); // Ensure it doesn't start with a number

    // Check if the variable name already exists
    let varName = baseName;
    let counter = 1;

    while (this.variableExists(sourceFile, varName)) {
      varName = `${baseName}_${counter}`;
      counter++;
    }

    return varName;
  }

  /**
   * Check if a variable name exists in the source file
   */
  private variableExists(sourceFile: SourceFile, varName: string): boolean {
    let exists = false;

    sourceFile.forEachDescendant((node) => {
      if (Node.isVariableDeclaration(node)) {
        const name = node.getName();
        if (name === varName) {
          exists = true;
        }
      } else if (Node.isParameterDeclaration(node)) {
        const name = node.getName();
        if (name === varName) {
          exists = true;
        }
      } else if (Node.isFunctionDeclaration(node)) {
        const name = node.getName();
        if (name === varName) {
          exists = true;
        }
      }
    });

    return exists;
  }

  /**
   * Get the transformed text of a source file
   */
  getTransformedText(sourceFile: SourceFile): string {
    return sourceFile.getFullText();
  }

  /**
   * Save all transformed files
   */
  async saveAll(): Promise<void> {
    await this.project.save();
  }

  /**
   * Transform Memory.read* and Memory.write* to ptr.read* and ptr.write*
   */
  private transformMemoryAPIs(sourceFile: SourceFile): void {
    const memoryMethods = new Set([
      "readU8",
      "readU16",
      "readU32",
      "readU64",
      "readS8",
      "readS16",
      "readS32",
      "readS64",
      "readFloat",
      "readDouble",
      "readPointer",
      "readByteArray",
      "readUtf8String",
      "readUtf16String",
      "readAnsiString",
      "readCString",
      "writeU8",
      "writeU16",
      "writeU32",
      "writeU64",
      "writeS8",
      "writeS16",
      "writeS32",
      "writeS64",
      "writeFloat",
      "writeDouble",
      "writePointer",
      "writeByteArray",
      "writeUtf8String",
      "writeUtf16String",
      "writeAnsiString",
    ]);

    sourceFile.forEachDescendant((node) => {
      if (Node.isCallExpression(node)) {
        const expression = node.getExpression();

        if (Node.isPropertyAccessExpression(expression)) {
          const object = expression.getExpression();
          const property = expression.getName();

          if (
            Node.isIdentifier(object) &&
            object.getText() === "Memory" &&
            memoryMethods.has(property)
          ) {
            const args = node.getArguments();
            if (!args.length) return;

            const ptrArg = args[0];
            const restArgs = args
              .slice(1)
              .map((a) => a.getText())
              .join(", ");

            // Transform Memory.readU32(ptr) → ptr.readU32()
            // Transform Memory.writeU32(ptr, value) → ptr.writeU32(value)
            node.replaceWithText(
              `${ptrArg.getText()}.${property}(${restArgs})`,
            );
          }
        }
      }
    });
  }

  /**
   * Transform Module.getBaseAddress / findBaseAddress to Process.getModuleByName().base
   */
  private transformModuleBaseAddress(sourceFile: SourceFile): void {
    const calls: Array<{
      call: CallExpression;
      moduleArg: Node;
      method: string;
    }> = [];

    sourceFile.forEachDescendant((node) => {
      if (Node.isCallExpression(node)) {
        const expression = node.getExpression();

        if (Node.isPropertyAccessExpression(expression)) {
          const object = expression.getExpression();
          const property = expression.getName();

          if (
            Node.isIdentifier(object) &&
            object.getText() === "Module" &&
            (property === "getBaseAddress" || property === "findBaseAddress")
          ) {
            const args = node.getArguments();
            if (args.length === 1) {
              const moduleArg = args[0];
              calls.push({ call: node, moduleArg, method: property });
            }
          }
        }
      }
    });

    // Transform calls
    for (const { call, moduleArg } of calls) {
      // Use the module argument as-is, whether it's a string literal or dynamic expression
      call.replaceWithText(
        `Process.getModuleByName(${moduleArg.getText()}).base`,
      );
    }
  }

  /**
   * Transform Module.ensureInitialized to Process.getModuleByName().ensureInitialized()
   */
  private transformModuleEnsureInitialized(sourceFile: SourceFile): void {
    sourceFile.forEachDescendant((node) => {
      if (Node.isCallExpression(node)) {
        const expression = node.getExpression();

        if (Node.isPropertyAccessExpression(expression)) {
          const object = expression.getExpression();
          const property = expression.getName();

          if (
            Node.isIdentifier(object) &&
            object.getText() === "Module" &&
            property === "ensureInitialized"
          ) {
            const args = node.getArguments();
            if (args.length === 1) {
              const moduleArg = args[0];
              node.replaceWithText(
                `Process.getModuleByName(${moduleArg.getText()}).ensureInitialized()`,
              );
            }
          }
        }
      }
    });
  }

  /**
   * Transform Module.getSymbolByName / findSymbolByName
   */
  private transformModuleSymbolAPIs(sourceFile: SourceFile): void {
    const calls: Array<{
      call: CallExpression;
      moduleArg: Node;
      symbolArg: Node;
      method: string;
    }> = [];

    sourceFile.forEachDescendant((node) => {
      if (Node.isCallExpression(node)) {
        const expression = node.getExpression();

        if (Node.isPropertyAccessExpression(expression)) {
          const object = expression.getExpression();
          const property = expression.getName();

          if (
            Node.isIdentifier(object) &&
            object.getText() === "Module" &&
            (property === "getSymbolByName" || property === "findSymbolByName")
          ) {
            const args = node.getArguments();
            if (args.length === 2) {
              const moduleArg = args[0];
              const symbolArg = args[1];

              calls.push({
                call: node,
                moduleArg,
                symbolArg,
                method: property,
              });
            }
          }
        }
      }
    });

    // Transform calls
    for (const { call, moduleArg, symbolArg, method } of calls) {
      // Use the module and symbol arguments as-is, whether they're literals or dynamic expressions
      call.replaceWithText(
        `Process.getModuleByName(${moduleArg.getText()}).${method}(${symbolArg.getText()})`,
      );
    }
  }

  /**
   * Transform legacy enumeration APIs with callbacks to modern array-returning APIs
   */
  private transformLegacyEnumerationAPIs(sourceFile: SourceFile): void {
    sourceFile.forEachDescendant((node) => {
      if (Node.isCallExpression(node)) {
        const expression = node.getExpression();

        if (Node.isPropertyAccessExpression(expression)) {
          const object = expression.getExpression();
          const property = expression.getName();
          const args = node.getArguments();

          // Check if it's a legacy-style enumeration call
          if (this.isLegacyEnumerationCall(object, property, args)) {
            this.transformLegacyEnumerationCall(node, object, property, args);
          }
        }
      }
    });
  }

  /**
   * Check if a call is a legacy-style enumeration call
   */
  private isLegacyEnumerationCall(
    object: Node,
    property: string,
    args: Node[],
  ): boolean {
    // Process.enumerateModules({onMatch, onComplete})
    // Process.enumerateThreads({onMatch, onComplete})
    // Process.enumerateRanges('rwx', {onMatch, onComplete})

    if (Node.isIdentifier(object) && object.getText() === "Process") {
      if (property === "enumerateModules" || property === "enumerateThreads") {
        return args.length === 1 && Node.isObjectLiteralExpression(args[0]);
      }
      if (property === "enumerateRanges") {
        return args.length === 2 && Node.isObjectLiteralExpression(args[1]);
      }
    }

    // Module.enumerateExports('module', {onMatch, onComplete})
    if (Node.isIdentifier(object) && object.getText() === "Module") {
      if (
        property === "enumerateExports" ||
        property === "enumerateImports" ||
        property === "enumerateSymbols"
      ) {
        return args.length === 2 && Node.isObjectLiteralExpression(args[1]);
      }
    }

    return false;
  }

  /**
   * Transform a legacy enumeration call to modern style
   */
  private transformLegacyEnumerationCall(
    node: CallExpression,
    object: Node,
    property: string,
    args: Node[],
  ): void {
    const objectText = object.getText();

    if (objectText === "Process") {
      if (property === "enumerateModules" || property === "enumerateThreads") {
        const callbacks = args[0];
        this.convertCallbacksToForEach(
          node,
          `${objectText}.${property}()`,
          callbacks,
        );
      } else if (property === "enumerateRanges") {
        const rangeArg = args[0].getText();
        const callbacks = args[1];
        this.convertCallbacksToForEach(
          node,
          `${objectText}.${property}(${rangeArg})`,
          callbacks,
        );
      }
    } else if (objectText === "Module") {
      // Module.enumerateExports('module', {...}) → Process.getModuleByName('module').enumerateExports().forEach(...)
      if (
        property === "enumerateExports" ||
        property === "enumerateImports" ||
        property === "enumerateSymbols"
      ) {
        const moduleArg = args[0].getText();
        const callbacks = args[1];
        this.convertCallbacksToForEach(
          node,
          `Process.getModuleByName(${moduleArg}).${property}()`,
          callbacks,
        );
      }
    }
  }

  /**
   * Convert callback-style to forEach
   */
  private convertCallbacksToForEach(
    node: CallExpression,
    enumerationCall: string,
    callbacks: Node,
  ): void {
    if (!Node.isObjectLiteralExpression(callbacks)) return;

    const properties = callbacks.getProperties();
    let onMatchBody: string | null = null;
    let onCompleteBody: string | null = null;

    for (const prop of properties) {
      if (Node.isPropertyAssignment(prop)) {
        const name = prop.getName();
        const initializer = prop.getInitializer();

        if (name === "onMatch" && initializer) {
          if (
            Node.isFunctionExpression(initializer) ||
            Node.isArrowFunction(initializer)
          ) {
            const params = initializer.getParameters();
            const paramName = params.length > 0 ? params[0].getName() : "item";
            const body = initializer.getBody();

            if (Node.isBlock(body)) {
              onMatchBody = body
                .getStatements()
                .map((s) => s.getText())
                .join("\n  ");
            } else {
              onMatchBody = body?.getText() || "";
            }

            onMatchBody = `${paramName} => {\n  ${onMatchBody}\n}`;
          }
        } else if (name === "onComplete" && initializer) {
          if (
            Node.isFunctionExpression(initializer) ||
            Node.isArrowFunction(initializer)
          ) {
            const body = initializer.getBody();

            if (Node.isBlock(body)) {
              onCompleteBody = body
                .getStatements()
                .map((s) => s.getText())
                .join("\n");
            }
          }
        }
      }
    }

    if (onMatchBody) {
      let replacement = `${enumerationCall}.forEach(${onMatchBody});`;

      if (onCompleteBody && onCompleteBody.trim()) {
        // Add onComplete logic after the forEach
        replacement = `${replacement}\n${onCompleteBody}`;
      }

      node.replaceWithText(replacement);
    }
  }

  /**
   * Add ObjC and Java bridge imports if they are used in the file
   */
  private addBridgeImports(sourceFile: SourceFile): void {
    let usesObjC = false;
    let usesJava = false;

    // Check if ObjC or Java are already imported
    const existingImports = sourceFile.getImportDeclarations();
    let hasObjCImport = false;
    let hasJavaImport = false;

    for (const importDecl of existingImports) {
      const moduleSpecifier = importDecl.getModuleSpecifierValue();
      if (moduleSpecifier === "frida-objc-bridge") {
        hasObjCImport = true;
      }
      if (moduleSpecifier === "frida-java-bridge") {
        hasJavaImport = true;
      }
    }

    // Scan the file for ObjC and Java usage
    sourceFile.forEachDescendant((node) => {
      if (Node.isIdentifier(node)) {
        const text = node.getText();
        if (text === "ObjC") {
          usesObjC = true;
        }
        if (text === "Java") {
          usesJava = true;
        }
      }
    });

    // Add imports at the beginning if needed
    const importsToAdd: string[] = [];

    if (usesJava && !hasJavaImport) {
      importsToAdd.push('import Java from "frida-java-bridge";');
    }

    if (usesObjC && !hasObjCImport) {
      importsToAdd.push('import ObjC from "frida-objc-bridge";');
    }

    if (importsToAdd.length > 0) {
      // Insert at the beginning of the file
      const importText = importsToAdd.join("\n") + "\n\n";

      // If there are existing imports, insert after them
      if (existingImports.length > 0) {
        const lastImport = existingImports[existingImports.length - 1];
        lastImport.replaceWithText(
          lastImport.getText() + "\n" + importsToAdd.join("\n"),
        );
      } else {
        // Insert at the very beginning
        sourceFile.insertStatements(0, importsToAdd);
      }
    }
  }
}
