import traverseModule from '@babel/traverse';
import * as t from '@babel/types';

const traverse = traverseModule.default ?? traverseModule;

const arithmetic = new Set([
  '+',
  '-',
  '*',
  '/',
  '%',
  '**',
  '|',
  '&',
  '^',
  '<<',
  '>>',
  '>>>',
]);
const comparisons = new Set(['<', '<=', '>', '>=', '==', '!=', '===', '!==']);

export class NumericAnalysisLimit extends Error {}

export function numericLoops(ast, scopes) {
  const bindings = new Set();
  let remaining = 50000;
  const spend = () => {
    if (--remaining < 0)
      throw new NumericAnalysisLimit('transform_analysis_limit');
  };
  let dynamicScope = false;
  traverse(ast, {
    WithStatement() {
      dynamicScope = true;
    },
    CallExpression(path) {
      if (t.isIdentifier(path.node.callee, { name: 'eval' }))
        dynamicScope = true;
    },
    VariableDeclarator(path) {
      if (t.isIdentifier(path.node.id) && literal(path.node.init))
        bindings.add(path.scope.getBinding(path.node.id.name));
    },
  });
  if (dynamicScope) bindings.clear();
  const binding = node =>
    t.isIdentifier(node) ? scopes.get(node)?.getBinding(node.name) : undefined;
  function literal(node) {
    spend();
    return (
      t.isNumericLiteral(node) ||
      (t.isUnaryExpression(node) &&
        ['+', '-', '~'].includes(node.operator) &&
        literal(node.argument))
    );
  }
  function reference(node, dependencies) {
    const value = binding(node);
    if (!bindings.has(value)) return false;
    dependencies?.add(value);
    return true;
  }
  function numeric(node, dependencies) {
    spend();
    return (
      t.isNumericLiteral(node) ||
      (t.isIdentifier(node) && reference(node, dependencies)) ||
      (t.isBinaryExpression(node) &&
        arithmetic.has(node.operator) &&
        numeric(node.left, dependencies) &&
        numeric(node.right, dependencies)) ||
      (t.isUnaryExpression(node) &&
        ['+', '-', '~'].includes(node.operator) &&
        numeric(node.argument, dependencies))
    );
  }
  function write(node, dependencies) {
    spend();
    return (
      (t.isUpdateExpression(node) && reference(node.argument, dependencies)) ||
      (t.isAssignmentExpression(node) &&
        reference(node.left, dependencies) &&
        (node.operator === '=' || arithmetic.has(node.operator.slice(0, -1))) &&
        numeric(node.right, dependencies))
    );
  }
  // Only locals initialized as numbers and never assigned any other kind of
  // value qualify. Request parameters and conversions remain instrumented.
  const dependents = new Map(),
    invalid = [];
  for (const candidate of bindings) {
    spend();
    const dependencies = new Set();
    if (
      !candidate ||
      candidate.constantViolations.some(path => !write(path.node, dependencies))
    )
      invalid.push(candidate);
    for (const dependency of dependencies) {
      spend();
      if (!dependents.has(dependency)) dependents.set(dependency, new Set());
      dependents.get(dependency).add(candidate);
    }
  }
  // Removing a numeric assumption only invalidates its reverse dependencies.
  // Each binding is removed once, including cycles and reverse assignment chains.
  for (let index = 0; index < invalid.length; index++) {
    spend();
    const candidate = invalid[index];
    if (!bindings.delete(candidate)) continue;
    for (const dependent of dependents.get(candidate) || []) {
      spend();
      if (bindings.has(dependent)) invalid.push(dependent);
    }
  }
  function test(node) {
    spend();
    return (
      node == null ||
      numeric(node) ||
      t.isIdentifier(node) ||
      t.isBooleanLiteral(node) ||
      (t.isBinaryExpression(node) &&
        comparisons.has(node.operator) &&
        [node.left, node.right].every(
          value => numeric(value) || t.isIdentifier(value) || t.isLiteral(value)
        ))
    );
  }
  function statement(node) {
    spend();
    if (!node || t.isEmptyStatement(node)) return true;
    if (t.isBlockStatement(node)) return node.body.every(statement);
    if (t.isExpressionStatement(node)) return write(node.expression);
    if (t.isVariableDeclaration(node))
      return node.declarations.every(
        declaration =>
          bindings.has(binding(declaration.id)) && numeric(declaration.init)
      );
    return false;
  }
  return {
    bindings,
    nativeLoop: node =>
      t.isForStatement(node) &&
      (t.isVariableDeclaration(node.init)
        ? statement(node.init)
        : !node.init || write(node.init)) &&
      test(node.test) &&
      (!node.update || write(node.update)) &&
      statement(node.body),
  };
}
