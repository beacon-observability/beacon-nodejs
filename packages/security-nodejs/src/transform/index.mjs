import { parse } from '@babel/parser';
import traverseModule from '@babel/traverse';
import generateModule from '@babel/generator';
import * as t from '@babel/types';
import { TraceMap, originalPositionFor } from '@jridgewell/trace-mapping';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { numericLoops, NumericAnalysisLimit } from './numeric.mjs';

const traverse = traverseModule.default ?? traverseModule;
const generate = generateModule.default ?? generateModule;

export function transform(
  source,
  filename,
  url = filename,
  inputSourceMap,
  format
) {
  try {
    return transformModule(source, filename, url, inputSourceMap, format);
  } catch (error) {
    if (!(error instanceof NumericAnalysisLimit)) throw error;
    return {
      code: source,
      sourceFiles: [],
      exportedFunctions: [],
      gaps: ['transform_analysis_limit'],
    };
  }
}

function transformModule(source, filename, url, inputSourceMap, format) {
  const sourceType =
    format === 'module' || (!format && filename.endsWith('.mjs'))
      ? 'module'
      : format === 'commonjs'
        ? 'script'
        : 'unambiguous';
  const ast = parse(source, {
    sourceType,
    sourceFilename: filename,
    allowReturnOutsideFunction: true,
    plugins: ['explicitResourceManagement'],
  });
  const workLimit = new Error('transform_node_limit');
  let nodes = 0;
  try {
    t.traverseFast(ast, () => {
      if (++nodes > 50000) throw workLimit;
    });
  } catch (error) {
    if (error !== workLimit) throw error;
    return {
      code: source,
      sourceFiles: [],
      exportedFunctions: [],
      gaps: ['transform_node_limit'],
    };
  }
  let uid = 0;
  // Babel restarts collision checks for each stem and strips trailing digits.
  // Distinct stems keep allocation linear while retaining its scope checks.
  const unique = (scope, name) =>
    scope.generateUidIdentifier(`security${++uid}${name}`);
  let evalBindingConflict = false;
  traverse(ast, {
    CallExpression(path) {
      if (
        t.isIdentifier(path.node.callee, { name: 'eval' }) &&
        ['globalThis', 'Symbol'].some(name => path.scope.getBinding(name))
      )
        evalBindingConflict = true;
    },
  });
  // Direct eval resolves names from source text, which Babel cannot rename.
  // Keep the module native if helper bootstrap bindings would change its scope.
  if (evalBindingConflict)
    return {
      code: source,
      sourceFiles: [],
      exportedFunctions: [],
      gaps: ['direct_eval_helper_binding'],
    };
  // The helper must also work when a cyclic ESM import calls a hoisted
  // function before this module's body initializes its top-level bindings.
  traverse(ast, {
    Scope(path) {
      for (const name of ['globalThis', 'Symbol']) {
        if (path.scope.hasOwnBinding(name))
          path.scope.rename(name, unique(path.scope, name).name);
      }
    },
  });
  const scopes = new WeakMap(),
    functionInfo = new WeakMap(),
    bindings = new Map(),
    imports = new Map(),
    names = new WeakMap(),
    strictness = new WeakMap();
  const initializedScopes = new WeakSet();
  let programScope;
  traverse(ast, {
    enter(path) {
      scopes.set(path.node, path.scope);
      strictness.set(path.node, path.isInStrictMode());
      if (path.isProgram()) programScope = path.scope;
      if (path.isFunction()) {
        functionInfo.set(path.node, {
          id: url + ':' + path.node.start,
          frame: unique(path.scope, 'Frame'),
        });
        const parent = path.parent;
        if (t.isVariableDeclarator(parent) && t.isIdentifier(parent.id))
          names.set(path.node, parent.id.name);
        else if (
          t.isAssignmentExpression(parent) &&
          t.isIdentifier(parent.left)
        )
          names.set(path.node, parent.left.name);
        else if (t.isObjectProperty(parent) && !parent.computed)
          names.set(path.node, String(parent.key.name ?? parent.key.value));
      }
      if (!initializedScopes.has(path.scope)) {
        initializedScopes.add(path.scope);
        for (const binding of Object.values(path.scope.bindings)) {
          if (!bindings.has(binding) && binding.kind !== 'module')
            bindings.set(
              binding,
              unique(binding.scope, binding.identifier.name + 'Marks')
            );
        }
      }
      if (path.isImportDeclaration())
        for (const item of path.node.specifiers) {
          imports.set(path.scope.getBinding(item.local.name), {
            source: path.node.source.value,
            name: t.isImportDefaultSpecifier(item)
              ? 'default'
              : t.isImportNamespaceSpecifier(item)
                ? '*'
                : item.imported.name || item.imported.value,
          });
        }
    },
  });
  const numeric = numericLoops(ast, scopes);
  for (const binding of numeric.bindings) bindings.delete(binding);
  const helper = unique(programScope, 'Context');
  const usedScopes = new Set();
  const exportedFunctions = [];
  const clone = node => t.cloneNode(node, true);
  const str = value => t.stringLiteral(String(value));
  const list = values => t.arrayExpression(values);
  const member = (node, key) => t.memberExpression(node, t.identifier(key));
  const call = (name, args = []) =>
    t.callExpression(member(clone(helper), name), args);
  const value = pair => member(pair, 'v');
  const marks = pair => member(pair, 'm');
  const pair = (v, m = list([])) => call('p', [v, m]);
  const sequence = items =>
    items.length === 1 ? items[0] : t.sequenceExpression(items);
  const assignment = (left, right) =>
    t.assignmentExpression('=', clone(left), right);
  const inputMap = inputSourceMap
    ? new TraceMap(inputSourceMap, pathToFileURL(filename).href)
    : undefined;
  const sourceFiles = new Set();
  const location = node => {
    const pos = node.loc?.start || { line: 1, column: 0 };
    if (inputMap) {
      const original = originalPositionFor(inputMap, pos);
      if (original.source && original.line != null) {
        const source = original.source.startsWith('file:')
          ? fileURLToPath(original.source)
          : original.source;
        sourceFiles.add(source);
        return source + '#' + original.line + ':' + (original.column || 0);
      }
    }
    return filename + '#' + pos.line + ':' + pos.column;
  };
  const scopeOf = (node, env) => scopes.get(node) || env.scope;
  const markOf = (node, env) =>
    bindings.get(scopeOf(node, env).getBinding(node.name));
  const temporary = env => {
    const id = unique(env.scope, 'Value');
    env.temps.push(id);
    return clone(id);
  };

  function readMarks(node, env) {
    const binding = scopeOf(node, env).getBinding(node.name),
      imp = imports.get(binding);
    if (imp)
      return imp.name === '*'
        ? list([])
        : call('importMarks', [str(url), str(imp.source), str(imp.name)]);
    return bindings.has(binding) ? clone(bindings.get(binding)) : list([]);
  }
  function patternBindings(
    pattern,
    path = [],
    output = [],
    rest = false,
    excluded = []
  ) {
    if (t.isIdentifier(pattern))
      output.push({ id: pattern, path, rest, excluded });
    else if (t.isAssignmentPattern(pattern))
      patternBindings(pattern.left, path, output, rest, excluded);
    else if (t.isRestElement(pattern))
      patternBindings(
        pattern.argument,
        path,
        output,
        rest || 'object',
        excluded
      );
    else if (t.isObjectPattern(pattern)) {
      const keys = pattern.properties
        .filter(p => !t.isRestElement(p) && !p.computed)
        .map(p => p.key.name ?? p.key.value)
        .map(String);
      for (const property of pattern.properties) {
        if (t.isRestElement(property))
          patternBindings(
            property.argument,
            [...path, ''],
            output,
            'object',
            keys
          );
        else if (
          !property.computed ||
          t.isStringLiteral(property.key) ||
          t.isNumericLiteral(property.key)
        )
          patternBindings(
            property.value,
            [...path, property.key.name ?? property.key.value],
            output
          );
      }
    } else if (t.isArrayPattern(pattern))
      pattern.elements.forEach((item, index) => {
        if (item)
          patternBindings(
            t.isRestElement(item) ? item.argument : item,
            [...path, index],
            output,
            t.isRestElement(item) ? 'array' : false
          );
      });
    return output;
  }
  function bindAssignments(pattern, origin, env) {
    return patternBindings(pattern).flatMap(info => {
      const mark = markOf(info.id, env);
      return mark
        ? [
            assignment(
              mark,
              call('binding', [
                clone(origin),
                t.valueToNode(info.path),
                clone(info.id),
                t.valueToNode(info.rest),
                t.valueToNode(info.excluded),
              ])
            ),
          ]
        : [];
    });
  }
  function scopePrelude(scope) {
    if (!scope || usedScopes.has(scope)) return [];
    usedScopes.add(scope);
    const declarations = [],
      functions = [];
    for (const binding of Object.values(scope.bindings)) {
      if (binding.scope !== scope || !bindings.has(binding)) continue;
      declarations.push(
        t.variableDeclarator(clone(bindings.get(binding)), list([]))
      );
      if (binding.path.isFunctionDeclaration()) {
        const info = functionInfo.get(binding.path.node);
        if (info)
          functions.push(
            t.expressionStatement(
              call('fn', [clone(binding.identifier), str(info.id)])
            )
          );
      }
    }
    return [
      ...(declarations.length
        ? [
            t.variableDeclaration(
              scope === programScope ? 'var' : 'let',
              declarations
            ),
          ]
        : []),
      ...functions,
    ];
  }
  function functionNode(node) {
    const info = functionInfo.get(node);
    if (!info) return node;
    if (node.generator) return node;
    const scope = scopes.get(node);
    const env = { scope, temps: [], frame: info.frame };
    const originalBody = node.body;
    const body = t.isBlockStatement(originalBody)
      ? block(originalBody, env)
      : t.blockStatement([
          t.returnStatement(
            call('ret', [clone(info.frame), expr(originalBody, env)])
          ),
        ]);
    const prefix = t.isBlockStatement(originalBody) ? [] : scopePrelude(scope);
    const params = [];
    node.params.forEach((param, index) => {
      let dynamicDefault = false;
      t.traverseFast(param, child => {
        if (
          t.isAssignmentPattern(child) &&
          (!t.isLiteral(child.right) ||
            (t.isTemplateLiteral(child.right) &&
              child.right.expressions.length))
        )
          dynamicDefault = true;
      });
      if (dynamicDefault)
        params.push(
          t.expressionStatement(
            call('defaultBoundary', [
              clone(info.frame),
              t.numericLiteral(index),
              t.booleanLiteral(
                !t.isAssignmentPattern(param) || !t.isIdentifier(param.left)
              ),
            ])
          )
        );
      for (const binding of patternBindings(
        t.isRestElement(param) ? param.argument : param
      )) {
        const mark = markOf(binding.id, env);
        if (!mark) continue;
        params.push(
          t.expressionStatement(
            assignment(
              mark,
              call('param', [
                clone(info.frame),
                t.numericLiteral(index),
                clone(binding.id),
                t.valueToNode(binding.path),
                t.valueToNode(
                  t.isRestElement(param) ? 'parameter' : binding.rest
                ),
                t.valueToNode(binding.excluded),
              ])
            )
          )
        );
      }
    });
    const preludeCount = scopePreludeCounts.get(body) || 0;
    const argumentMetadata = [];
    if (!t.isArrowFunctionExpression(node) && !scope.getBinding('arguments')) {
      argumentMetadata.push(t.identifier('arguments'));
      if (
        !strictness.get(node) &&
        !originalBody.directives?.some(d => d.value.value === 'use strict') &&
        node.params.every(param => t.isIdentifier(param))
      ) {
        const aliases = node.params.flatMap((param, index) => {
          const mark = markOf(param, env);
          if (
            !mark ||
            node.params.findLastIndex(p => p.name === param.name) !== index
          )
            return [];
          const m = unique(scope, 'Marks');
          return [
            list([
              t.numericLiteral(index),
              t.arrowFunctionExpression([], clone(mark)),
              t.arrowFunctionExpression([clone(m)], assignment(mark, clone(m))),
            ]),
          ];
        });
        argumentMetadata.push(list(aliases));
      }
    }
    body.body.splice(
      preludeCount,
      0,
      ...prefix,
      t.variableDeclaration('const', [
        t.variableDeclarator(
          clone(info.frame),
          call('enter', [
            str(info.id),
            ...(t.isFunctionDeclaration(node) && node.id
              ? [clone(node.id)]
              : []),
          ])
        ),
      ]),
      ...params,
      t.expressionStatement(
        call('entered', [clone(info.frame), ...argumentMetadata])
      )
    );
    if (env.temps.length)
      body.body.unshift(
        t.variableDeclaration(
          'let',
          env.temps.map(id => t.variableDeclarator(clone(id)))
        )
      );
    body.body.unshift(helperDeclaration());
    node.body = body;
    return node;
  }
  function classNode(node) {
    const registrations = [];
    for (const method of node.body.body) {
      if (!t.isClassMethod(method)) continue;
      const info = functionInfo.get(method);
      functionNode(method);
      if (method.kind === 'constructor')
        registrations.push(
          t.expressionStatement(call('fn', [t.thisExpression(), str(info.id)]))
        );
      else if (!method.computed)
        registrations.push(
          t.expressionStatement(
            call('method', [
              method.static
                ? t.thisExpression()
                : member(t.thisExpression(), 'prototype'),
              t.valueToNode(method.key.name ?? method.key.value),
              str(info.id),
              str(method.kind === 'method' ? 'value' : method.kind),
            ])
          )
        );
    }
    if (registrations.length) node.body.body.push(t.staticBlock(registrations));
    return node;
  }
  function optional(node, env, isCall) {
    const temp = temporary(env);
    const input = isCall ? node.callee : node.object;
    const check = member(clone(temp), 'skip');
    const test = node.optional
      ? t.logicalExpression(
          '||',
          check,
          t.binaryExpression('==', value(clone(temp)), t.nullLiteral())
        )
      : check;
    const next = isCall
      ? call('invoke', [
          clone(temp),
          args(node.arguments, env),
          str(location(node)),
        ])
      : call('get', [
          clone(temp),
          node.computed
            ? expr(node.property, env)
            : pair(str(node.property.name)),
          str(location(node)),
        ]);
    return sequence([
      assignment(temp, isCall ? callee(input, env) : expr(input, env)),
      t.conditionalExpression(test, call('skipped'), next),
    ]);
  }
  function args(items, env) {
    return list(
      items.map(item =>
        t.isSpreadElement(item)
          ? t.spreadElement(call('spread', [expr(item.argument, env)]))
          : expr(item, env)
      )
    );
  }
  function callee(node, env) {
    const result = expr(node, env);
    return t.isMemberExpression(node) || t.isOptionalMemberExpression(node)
      ? result
      : call('unref', [result]);
  }
  function reference(node, env, deferKey = false) {
    const object = temporary(env),
      key = temporary(env);
    const property = node.computed
      ? expr(node.property, env)
      : pair(str(node.property.name));
    return {
      object,
      key,
      init: [
        assignment(object, expr(node.object, env)),
        assignment(
          key,
          deferKey ? property : call('key', [clone(object), property])
        ),
      ],
    };
  }
  function assign(node, env) {
    const temp = temporary(env);
    if (t.isIdentifier(node.left)) {
      const mark = markOf(node.left, env);
      const result =
        node.operator === '='
          ? expr(node.right, env)
          : ['&&=', '||=', '??='].includes(node.operator)
            ? null
            : call('binary', [
                str(node.operator.slice(0, -1)),
                expr(node.left, env),
                expr(node.right, env),
                str(location(node)),
              ]);
      const writes = [
        assignment(temp, result || expr(node.right, env)),
        assignment(node.left, value(clone(temp))),
        ...(mark ? [assignment(mark, marks(clone(temp)))] : []),
        clone(temp),
      ];
      if (result) return sequence(writes);
      const left = expr(node.left, env),
        before = temporary(env);
      const test =
        node.operator === '&&='
          ? value(clone(before))
          : node.operator === '||='
            ? t.unaryExpression('!', value(clone(before)))
            : t.binaryExpression('==', value(clone(before)), t.nullLiteral());
      return sequence([
        assignment(before, left),
        t.conditionalExpression(test, sequence(writes), clone(before)),
      ]);
    }
    if (
      t.isMemberExpression(node.left) &&
      !t.isSuper(node.left.object) &&
      !t.isPrivateName(node.left.property)
    ) {
      const ref = reference(node.left, env, true);
      if (node.operator === '=')
        return sequence([
          ...ref.init,
          call('set', [
            clone(ref.object),
            clone(ref.key),
            expr(node.right, env),
            t.booleanLiteral(strictness.get(node) || false),
          ]),
        ]);
      const before = temporary(env);
      const read = assignment(
        before,
        call('get', [clone(ref.object), clone(ref.key), str(location(node))])
      );
      const set = right =>
        call('set', [
          clone(ref.object),
          clone(ref.key),
          right,
          t.booleanLiteral(strictness.get(node) || false),
        ]);
      if (['&&=', '||=', '??='].includes(node.operator)) {
        const test =
          node.operator === '&&='
            ? value(clone(before))
            : node.operator === '||='
              ? t.unaryExpression('!', value(clone(before)))
              : t.binaryExpression('==', value(clone(before)), t.nullLiteral());
        return sequence([
          ...ref.init,
          read,
          t.conditionalExpression(
            test,
            set(expr(node.right, env)),
            clone(before)
          ),
        ]);
      }
      return sequence([
        ...ref.init,
        read,
        set(
          call('binary', [
            str(node.operator.slice(0, -1)),
            clone(before),
            expr(node.right, env),
            str(location(node)),
          ])
        ),
      ]);
    }
    if (t.isObjectPattern(node.left) || t.isArrayPattern(node.left))
      return sequence([
        assignment(temp, expr(node.right, env)),
        t.assignmentExpression('=', node.left, value(clone(temp))),
        ...bindAssignments(node.left, temp, env),
        clone(temp),
      ]);
    return pair(node);
  }
  function expr(node, env) {
    if (!node) return pair(t.unaryExpression('void', t.numericLiteral(0)));
    if (t.isIdentifier(node)) {
      const imp = imports.get(scopeOf(node, env).getBinding(node.name));
      const result = pair(
        imp && imp.name !== '*'
          ? call('importValue', [
              clone(node),
              str(url),
              str(imp.source),
              str(imp.name),
            ])
          : clone(node),
        readMarks(node, env)
      );
      return imp?.name === '*'
        ? call('namespace', [result, str(url), str(imp.source)])
        : result;
    }
    if (
      (t.isLiteral(node) && !t.isTemplateLiteral(node)) ||
      t.isThisExpression(node) ||
      t.isMetaProperty(node)
    )
      return pair(clone(node));
    if (t.isFunctionExpression(node) || t.isArrowFunctionExpression(node)) {
      const info = functionInfo.get(node),
        named = node.id?.name || names.get(node) || '';
      return pair(call('fn', [functionNode(node), str(info.id), str(named)]));
    }
    if (t.isClassExpression(node)) return pair(classNode(node));
    if (
      t.isOptionalMemberExpression(node) ||
      t.isOptionalCallExpression(node)
    ) {
      let privateChain = false;
      t.traverseFast(node, child => {
        if (t.isPrivateName(child)) privateChain = true;
      });
      if (privateChain)
        return sequence([
          call('gap', [str('private_optional_chain')]),
          pair(node),
        ]);
      return optional(node, env, t.isOptionalCallExpression(node));
    }
    if (
      t.isMemberExpression(node) &&
      !t.isSuper(node.object) &&
      !t.isPrivateName(node.property)
    )
      return call('get', [
        expr(node.object, env),
        node.computed
          ? expr(node.property, env)
          : pair(str(node.property.name)),
        str(location(node)),
      ]);
    if (t.isCallExpression(node) || t.isNewExpression(node)) {
      if (
        t.isSuper(node.callee) ||
        t.isImport(node.callee) ||
        t.isIdentifier(node.callee, { name: 'eval' }) ||
        (t.isMemberExpression(node.callee) &&
          (t.isSuper(node.callee.object) ||
            t.isPrivateName(node.callee.property)))
      )
        return sequence([
          call('gap', [str('dynamic_or_private_call')]),
          pair(node),
        ]);
      return call('invoke', [
        callee(node.callee, env),
        args(node.arguments, env),
        str(location(node)),
        t.booleanLiteral(t.isNewExpression(node)),
      ]);
    }
    if (t.isBinaryExpression(node))
      return call('binary', [
        str(node.operator),
        expr(node.left, env),
        expr(node.right, env),
        str(location(node)),
      ]);
    if (t.isLogicalExpression(node)) {
      const temp = temporary(env);
      const condition =
        node.operator === '&&'
          ? value(clone(temp))
          : node.operator === '||'
            ? t.unaryExpression('!', value(clone(temp)))
            : t.binaryExpression('==', value(clone(temp)), t.nullLiteral());
      return sequence([
        assignment(temp, expr(node.left, env)),
        t.conditionalExpression(condition, expr(node.right, env), clone(temp)),
      ]);
    }
    if (t.isConditionalExpression(node))
      return t.conditionalExpression(
        value(expr(node.test, env)),
        expr(node.consequent, env),
        expr(node.alternate, env)
      );
    if (t.isSequenceExpression(node))
      return sequence(
        node.expressions.map((item, i) =>
          i === node.expressions.length - 1
            ? expr(item, env)
            : value(expr(item, env))
        )
      );
    if (t.isAssignmentExpression(node)) return assign(node, env);
    if (t.isUnaryExpression(node)) {
      if (
        node.operator === 'typeof' &&
        t.isIdentifier(node.argument) &&
        !scopeOf(node.argument, env).getBinding(node.argument.name)
      )
        return pair(node);
      if (node.operator === 'delete') {
        if (t.isMemberExpression(node.argument)) {
          const ref = reference(node.argument, env);
          return sequence([
            ...ref.init,
            call('del', [
              clone(ref.object),
              clone(ref.key),
              t.booleanLiteral(strictness.get(node) || false),
            ]),
          ]);
        }
        return pair(node);
      }
      return call('unary', [
        str(node.operator),
        expr(node.argument, env),
        str(location(node)),
      ]);
    }
    if (t.isUpdateExpression(node)) {
      const update = temporary(env);
      const calculation = input =>
        assignment(
          update,
          call('updateValue', [
            input,
            t.booleanLiteral(node.operator === '++'),
            str(location(node)),
          ])
        );
      const after = () => member(clone(update), 'after');
      const result = () =>
        member(clone(update), node.prefix ? 'after' : 'before');
      if (t.isIdentifier(node.argument)) {
        const mark = markOf(node.argument, env);
        return sequence([
          calculation(expr(node.argument, env)),
          assignment(node.argument, value(after())),
          ...(mark ? [assignment(mark, marks(after()))] : []),
          result(),
        ]);
      }
      if (
        t.isMemberExpression(node.argument) &&
        !t.isPrivateName(node.argument.property) &&
        !t.isSuper(node.argument.object)
      ) {
        const ref = reference(node.argument, env, true);
        return sequence([
          ...ref.init,
          calculation(
            call('get', [
              clone(ref.object),
              clone(ref.key),
              str(location(node)),
            ])
          ),
          call('set', [
            clone(ref.object),
            clone(ref.key),
            after(),
            t.booleanLiteral(strictness.get(node) || false),
          ]),
          result(),
        ]);
      }
      return sequence([
        call('gap', [str('property_update_propagation')]),
        pair(node),
      ]);
    }
    if (t.isAwaitExpression(node)) {
      const temp = temporary(env);
      return sequence([
        assignment(temp, expr(node.argument, env)),
        call('awaited', [clone(temp), t.awaitExpression(value(clone(temp)))]),
      ]);
    }
    if (t.isTemplateLiteral(node)) {
      const parts = [];
      node.quasis.forEach((quasi, i) => {
        parts.push(str(quasi.value.cooked ?? quasi.value.raw));
        if (node.expressions[i])
          parts.push(
            call('string', [
              expr(node.expressions[i], env),
              str(location(node.expressions[i])),
            ])
          );
      });
      return call('template', [list(parts), str(location(node))]);
    }
    if (t.isArrayExpression(node)) {
      if (node.elements.some(item => item === null))
        return sequence([
          call('gap', [str('sparse_array_propagation')]),
          pair(node),
        ]);
      return call('array', [args(node.elements, env)]);
    }
    if (t.isObjectExpression(node)) {
      const entries = [],
        methods = [],
        properties = [];
      for (const prop of node.properties) {
        if (t.isSpreadElement(prop)) {
          const temp = temporary(env);
          properties.push(
            t.spreadElement(value(assignment(temp, expr(prop.argument, env))))
          );
          entries.push(
            list([t.nullLiteral(), clone(temp), t.booleanLiteral(true)])
          );
        } else if (t.isObjectMethod(prop)) {
          const info = functionInfo.get(prop);
          properties.push(functionNode(prop));
          if (!prop.computed)
            methods.push({
              key: prop.key.name ?? prop.key.value,
              id: info.id,
              kind: prop.kind === 'method' ? 'value' : prop.kind,
            });
        } else {
          const temp = temporary(env),
            key = prop.computed ? temporary(env) : null;
          const protoData =
            prop.shorthand && t.isIdentifier(prop.key, { name: '__proto__' });
          properties.push(
            t.objectProperty(
              key
                ? value(assignment(key, expr(prop.key, env)))
                : protoData
                  ? str('__proto__')
                  : prop.key,
              value(assignment(temp, expr(prop.value, env))),
              prop.computed || protoData
            )
          );
          entries.push(
            list([
              key
                ? value(clone(key))
                : t.valueToNode(prop.key.name ?? prop.key.value),
              clone(temp),
              t.booleanLiteral(false),
            ])
          );
        }
      }
      let result = call('object', [
        t.objectExpression(properties),
        list(entries),
      ]);
      if (methods.length) {
        const temp = temporary(env);
        result = sequence([
          assignment(temp, result),
          ...methods.map(m =>
            call('method', [
              value(clone(temp)),
              t.valueToNode(m.key),
              str(m.id),
              str(m.kind),
            ])
          ),
          clone(temp),
        ]);
      }
      return result;
    }
    if (t.isImportExpression(node))
      return pair(
        t.importExpression(
          value(expr(node.source, env)),
          node.options ? value(expr(node.options, env)) : null
        )
      );
    return sequence([
      call('gap', [str('unmodeled_syntax:' + node.type)]),
      pair(node),
    ]);
  }
  const scopePreludeCounts = new WeakMap();
  function variable(node, env, forInit = false) {
    const declarations = [];
    for (const declaration of node.declarations) {
      if (!declaration.init) {
        declarations.push(declaration);
        if (forInit)
          for (const info of patternBindings(declaration.id)) {
            const mark = markOf(info.id, env);
            if (mark)
              declarations.push(t.variableDeclarator(clone(mark), list([])));
          }
        continue;
      }
      const temp = temporary(env);
      if (forInit) {
        declaration.init = value(assignment(temp, expr(declaration.init, env)));
        declarations.push(declaration);
        for (const info of patternBindings(declaration.id)) {
          const mark = markOf(info.id, env);
          if (mark)
            declarations.push(
              t.variableDeclarator(
                clone(mark),
                call('binding', [
                  clone(temp),
                  t.valueToNode(info.path),
                  clone(info.id),
                  t.valueToNode(info.rest),
                  t.valueToNode(info.excluded),
                ])
              )
            );
        }
      } else if (t.isIdentifier(declaration.id)) {
        const mark = markOf(declaration.id, env);
        declaration.init = sequence([
          assignment(temp, expr(declaration.init, env)),
          ...(mark ? [assignment(mark, marks(clone(temp)))] : []),
          value(clone(temp)),
        ]);
        declarations.push(declaration);
      } else {
        declaration.init = value(assignment(temp, expr(declaration.init, env)));
        declarations.push(declaration);
        const effects = bindAssignments(declaration.id, temp, env);
        if (effects.length)
          declarations.push(
            t.variableDeclarator(
              unique(env.scope, 'Binding'),
              sequence([...effects, t.numericLiteral(0)])
            )
          );
      }
    }
    node.declarations = declarations;
    return node;
  }
  function statement(node, env) {
    if (!node) return node;
    if (numeric.nativeLoop(node)) return node;
    if (t.isBlockStatement(node)) return block(node, env);
    if (t.isVariableDeclaration(node)) return variable(node, env);
    if (t.isFunctionDeclaration(node)) return functionNode(node);
    if (t.isExpressionStatement(node)) {
      node.expression = value(expr(node.expression, env));
      return node;
    }
    if (t.isReturnStatement(node)) {
      node.argument = env.frame
        ? call('ret', [clone(env.frame), expr(node.argument, env)])
        : value(expr(node.argument, env));
      return node;
    }
    if (t.isThrowStatement(node)) {
      node.argument = call('thrown', [expr(node.argument, env)]);
      return node;
    }
    if (t.isIfStatement(node)) {
      node.test = value(expr(node.test, env));
      node.consequent = statement(node.consequent, env);
      node.alternate = statement(node.alternate, env);
      return node;
    }
    if (t.isWhileStatement(node) || t.isDoWhileStatement(node)) {
      node.test = value(expr(node.test, env));
      node.body = statement(node.body, env);
      return node;
    }
    if (t.isForStatement(node)) {
      if (node.init)
        node.init = t.isVariableDeclaration(node.init)
          ? variable(node.init, env, ['let', 'const'].includes(node.init.kind))
          : value(expr(node.init, env));
      if (node.test) node.test = value(expr(node.test, env));
      if (node.update) node.update = value(expr(node.update, env));
      node.body = statement(node.body, env);
      return node;
    }
    if (t.isForOfStatement(node) || t.isForInStatement(node)) {
      const body = statement(node.body, env),
        statements = t.isBlockStatement(body) ? body.body : [body];
      const iterator = temporary(env),
        isOf = t.isForOfStatement(node) && !node.await;
      node.right = isOf
        ? member(
            assignment(iterator, call('iterator', [expr(node.right, env)])),
            'iterable'
          )
        : node.await
          ? sequence([
              call('gap', [str('async_iterator_propagation')]),
              value(expr(node.right, env)),
            ])
          : value(expr(node.right, env));
      const pattern = t.isVariableDeclaration(node.left)
        ? node.left.declarations[0].id
        : node.left;
      const declarations = [];
      for (const info of patternBindings(pattern)) {
        const mark = markOf(info.id, env);
        if (!mark) continue;
        const m = isOf
          ? call('binding', [
              pair(
                member(clone(iterator), 'value'),
                member(clone(iterator), 'marks')
              ),
              t.valueToNode(info.path),
              clone(info.id),
              t.valueToNode(info.rest),
              t.valueToNode(info.excluded),
            ])
          : list([]);
        declarations.push(
          t.isVariableDeclaration(node.left) && node.left.kind !== 'var'
            ? t.variableDeclaration('let', [
                t.variableDeclarator(clone(mark), m),
              ])
            : t.expressionStatement(assignment(mark, m))
        );
      }
      node.body = t.blockStatement([...declarations, ...statements]);
      return node;
    }
    if (t.isTryStatement(node)) {
      node.block = block(node.block, env);
      if (node.handler) node.handler.body = block(node.handler.body, env);
      if (node.finalizer) node.finalizer = block(node.finalizer, env);
      return node;
    }
    if (t.isSwitchStatement(node)) {
      node.discriminant = value(expr(node.discriminant, env));
      for (const branch of node.cases) {
        if (branch.test) branch.test = value(expr(branch.test, env));
        branch.consequent = branch.consequent.map(s => statement(s, env));
      }
      const prefix = scopePrelude(scopes.get(node));
      return prefix.length ? t.blockStatement([...prefix, node]) : node;
    }
    if (t.isLabeledStatement(node)) {
      node.body = statement(node.body, env);
      return node;
    }
    if (t.isExportNamedDeclaration(node)) {
      if (
        t.isVariableDeclaration(node.declaration) &&
        node.declaration.declarations.some(d => !t.isIdentifier(d.id))
      ) {
        const originalNames = Object.keys(
          t.getBindingIdentifiers(node.declaration)
        );
        const declaration = statement(node.declaration, env);
        return [
          declaration,
          t.exportNamedDeclaration(
            null,
            originalNames.map(name =>
              t.exportSpecifier(t.identifier(name), t.identifier(name))
            )
          ),
        ];
      }
      if (node.declaration) node.declaration = statement(node.declaration, env);
      return node;
    }
    if (t.isExportDefaultDeclaration(node)) {
      if (t.isFunctionDeclaration(node.declaration)) {
        exportedFunctions.push({
          name: 'default',
          id: functionInfo.get(node.declaration).id,
        });
        node.declaration = functionNode(node.declaration);
      } else if (t.isClassDeclaration(node.declaration))
        node.declaration = classNode(node.declaration);
      else
        node.declaration = call('defaultExport', [
          str(url),
          expr(node.declaration, env),
        ]);
      return node;
    }
    if (t.isClassDeclaration(node)) return classNode(node);
    return node;
  }
  function block(node, env) {
    const prefix = scopePrelude(scopes.get(node));
    node.body = [...prefix, ...node.body.flatMap(s => statement(s, env))];
    scopePreludeCounts.set(node, prefix.length);
    return node;
  }
  const root = { scope: programScope, temps: [], frame: null };
  function helperDeclaration() {
    return t.variableDeclaration('const', [
      t.variableDeclarator(
        clone(helper),
        t.memberExpression(
          t.identifier('globalThis'),
          t.callExpression(
            t.memberExpression(t.identifier('Symbol'), t.identifier('for')),
            [str('beacon.security.helpers.v1')]
          ),
          true
        )
      ),
    ]);
  }
  const exportRegistrations = [];
  for (const node of ast.program.body) {
    if (t.isExportNamedDeclaration(node)) {
      const names = node.declaration
        ? Object.values(t.getBindingIdentifiers(node.declaration)).map(id => ({
            local: id,
            exported: id.name,
          }))
        : node.specifiers
            .filter(s => t.isExportSpecifier(s))
            .map(s => ({
              local: s.local,
              exported: s.exported.name || s.exported.value,
            }));
      for (const item of names)
        exportRegistrations.push(
          t.expressionStatement(
            call('exportMarks', [
              str(url),
              str(item.exported),
              t.arrowFunctionExpression(
                [],
                node.source
                  ? call('importMarks', [
                      str(url),
                      node.source,
                      str(item.local.name || item.local.value),
                    ])
                  : readMarks(item.local, root)
              ),
            ])
          )
        );
    } else if (
      t.isExportDefaultDeclaration(node) &&
      t.isFunctionDeclaration(node.declaration) &&
      node.declaration.id
    )
      exportRegistrations.push(
        t.expressionStatement(
          call('exportMarks', [
            str(url),
            str('default'),
            t.arrowFunctionExpression([], list([])),
          ])
        )
      );
    else if (t.isExportAllDeclaration(node))
      exportRegistrations.push(
        t.expressionStatement(call('exportAll', [str(url), node.source]))
      );
  }
  const prefix = scopePrelude(programScope);
  ast.program.body = ast.program.body.flatMap(node => statement(node, root));
  ast.program.body.unshift(
    helperDeclaration(),
    ...(root.temps.length
      ? [
          t.variableDeclaration(
            'let',
            root.temps.map(id => t.variableDeclarator(clone(id)))
          ),
        ]
      : []),
    ...prefix,
    ...exportRegistrations
  );
  const result = generate(
    ast,
    {
      sourceMaps: true,
      sourceFileName: filename,
      comments: true,
      inputSourceMap,
    },
    source
  );
  return {
    code:
      result.code +
      '\n//# sourceMappingURL=data:application/json;base64,' +
      Buffer.from(
        JSON.stringify({ ...result.map, sourcesContent: undefined })
      ).toString('base64'),
    map: result.map,
    sourceFiles: [...sourceFiles],
    exportedFunctions,
  };
}
