import { text } from '../config.mjs';

const shells = new Set(['sh', 'bash', 'dash', 'ksh', 'zsh']);
const shellWords = new Set([
  'if',
  'then',
  'else',
  'elif',
  'fi',
  'for',
  'while',
  'until',
  'case',
  'esac',
  'do',
  'done',
  'function',
]);
export const evidence = (status, reason) => ({
  status,
  reason,
  outcome: 'not_assessed',
});
export function evidenceStatus(event) {
  const status = event?.attack_evidence?.status;
  return ['suspected', 'no_evidence'].includes(status) ? status : 'unknown';
}
export const evidenceRank = event =>
  ({ no_evidence: 0, unknown: 1, suspected: 2 })[evidenceStatus(event)];

export function analyze(rule, role, value, marks, shell = 'unknown') {
  try {
    if (rule === 'sql_injection') {
      if (text('beacon.security.analysis.sql.dialect', 'unknown') !== 'ansi')
        return evidence('unknown', 'sql_dialect_unsupported');
      return lexical(value, marks, false);
    }
    if (rule === 'command_injection') {
      if (!shells.has(shell))
        return evidence('unknown', 'shell_dialect_unsupported');
      return lexical(value, marks, true);
    }
    if (
      ['command_execution', 'http_request_input'].includes(rule) &&
      marks.some(mark => !mark.exact)
    )
      return evidence('unknown', 'taint_imprecise');
    if (rule === 'command_execution')
      return evidence(
        role === 'argument' ? 'no_evidence' : 'unknown',
        role === 'argument'
          ? 'non_control_argument'
          : 'executable_policy_unavailable'
      );
    if (rule === 'http_request_input')
      return evidence('no_evidence', 'http_path_query_only');
    if (rule === 'ssrf')
      return evidence('unknown', 'network_policy_unavailable');
    if (rule === 'path_traversal')
      return evidence('unknown', 'path_policy_unavailable');
    return evidence('unknown', 'analysis_unavailable');
  } catch {
    return evidence('unknown', 'analysis_failed');
  }
}

function lexical(value, marks, shell) {
  if (typeof value !== 'string')
    return evidence('unknown', 'input_unavailable');
  if (value.length > 8192 || marks.length > 64)
    return evidence('unknown', 'analysis_budget');
  if (!marks.length) return evidence('unknown', 'taint_unavailable');
  const tainted = new Uint8Array(value.length);
  for (const mark of marks) {
    if (
      !mark.exact ||
      mark.unit !== 'utf16_code_unit' ||
      !Number.isSafeInteger(mark.start) ||
      !Number.isSafeInteger(mark.end) ||
      mark.start < 0 ||
      mark.end > value.length ||
      mark.start >= mark.end
    )
      return evidence('unknown', 'taint_imprecise');
    tainted.fill(1, mark.start, mark.end);
  }
  let quote = '',
    suspected = false,
    identifier = false,
    commandStart = true,
    parentheses = 0;
  const whitespace = ch => /\s/u.test(ch);
  const letter = ch => /\p{L}/u.test(ch);
  const digit = ch => ch >= '0' && ch <= '9';
  for (let i = 0; i < value.length; i++) {
    const ch = value[i],
      next = value[i + 1] || '';
    const code = ch.charCodeAt(0);
    if ((code < 32 && !'\n\r\t'.includes(ch)) || (code >= 127 && code <= 159))
      return evidence('unknown', 'syntax_unsupported');
    if (shell && ch === '\\' && quote !== "'") {
      if (++i >= value.length) return evidence('unknown', 'syntax_incomplete');
      if (quote === '"' && !'$`"\\\n'.includes(value[i])) i--;
      continue;
    }
    if (shell && quote !== "'" && '$`'.includes(ch))
      return evidence('unknown', 'shell_expansion_unsupported');
    if (!shell && '\\$`[]'.includes(ch))
      return evidence('unknown', 'sql_syntax_unsupported');
    if (quote) {
      if (ch === quote) {
        if (!shell && next === quote) i++;
        else quote = '';
      } else if (!shell && quote === '"' && tainted[i]) identifier = true;
      continue;
    }
    if (ch === "'" || ch === '"') {
      commandStart = false;
      quote = ch;
      continue;
    }
    if (shell) {
      if ('*?[]~'.includes(ch))
        return evidence('unknown', 'shell_expansion_unsupported');
      if ('(){}<>'.includes(ch))
        return evidence('unknown', 'shell_syntax_unsupported');
      if (ch === '#' && (i === 0 || whitespace(value[i - 1]))) {
        while (i < value.length && value[i] !== '\n') i++;
        i--;
        continue;
      }
      if (';|&\n'.includes(ch)) {
        suspected ||= Boolean(tainted[i]);
        commandStart = true;
      } else if (commandStart && !whitespace(ch)) {
        let end = i;
        while (end < value.length && letter(value[end])) end++;
        if (shellWords.has(value.slice(i, end)))
          return evidence('unknown', 'shell_syntax_unsupported');
        commandStart = false;
      }
    } else {
      if ((ch === '-' && next === '-') || (ch === '/' && next === '*')) {
        suspected ||= Boolean(tainted[i] || tainted[i + 1]);
        if (ch === '-') {
          while (i < value.length && value[i] !== '\n') i++;
        } else {
          const end = value.indexOf('*/', i + 2);
          if (end < 0) return evidence('unknown', 'syntax_incomplete');
          if (value.slice(i + 2, end).includes('/*'))
            return evidence('unknown', 'sql_syntax_unsupported');
          i = end + 1;
        }
        continue;
      }
      if (ch === '(') parentheses++;
      else if (ch === ')' && --parentheses < 0)
        return evidence('unknown', 'syntax_incomplete');
      let previous = i - 1;
      while (previous >= 0 && whitespace(value[previous])) previous--;
      const numericSign = previous < 0 || '=<>(,'.includes(value[previous]);
      if (digit(ch) || ('-+'.includes(ch) && digit(next) && numericSign)) {
        let decimal = false;
        while (
          i + 1 < value.length &&
          (digit(value[i + 1]) || value[i + 1] === '.')
        ) {
          i++;
          if (value[i] === '.') {
            if (decimal) return evidence('unknown', 'sql_syntax_unsupported');
            decimal = true;
          }
        }
        continue;
      }
      if (letter(ch) || ch === '_') {
        do {
          identifier ||= Boolean(tainted[i]);
          i++;
        } while (
          i < value.length &&
          (letter(value[i]) || digit(value[i]) || value[i] === '_')
        );
        i--;
        continue;
      }
      if (!'=<>!;|&+-*/(),.?'.includes(ch) && !whitespace(ch))
        return evidence('unknown', 'sql_syntax_unsupported');
      if (tainted[i] && '=<>!;|&+-*/(),'.includes(ch)) suspected = true;
    }
  }
  if (quote || parentheses) return evidence('unknown', 'syntax_incomplete');
  if (suspected)
    return evidence(
      'suspected',
      shell ? 'tainted_shell_control' : 'tainted_sql_structure'
    );
  if (identifier) return evidence('unknown', 'sql_identifier_control');
  return evidence('no_evidence', shell ? 'shell_data_only' : 'sql_data_only');
}
