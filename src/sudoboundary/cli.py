"""SudoBoundary command line interface."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .core import (InputError, VERSION, audit_report, compare, evaluate, gate,
                   load_json, sarif, validate_policy, validate_queries, validate_request, _finding)


def _arguments() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog='sudoboundary', description='Auditoria offline de políticas declarativas de privilégios Linux')
    p.add_argument('--version', action='version', version=f'SudoBoundary {VERSION}')
    sp = p.add_subparsers(dest='command', required=True)
    for name in ('audit', 'explain', 'compare', 'assert'):
        sub = sp.add_parser(name)
        if name == 'compare':
            sub.add_argument('--baseline', required=True)
            sub.add_argument('--candidate', required=True)
            sub.add_argument('--queries', required=True)
        else:
            sub.add_argument('--policy', required=True)
        if name == 'explain':
            sub.add_argument('--request', required=True)
        if name == 'assert':
            sub.add_argument('--queries', required=True)
        if name in ('audit', 'compare'):
            sub.add_argument('--fail-on', choices=['none', 'low', 'medium', 'high', 'critical'], default='high')
            sub.add_argument('--sarif', help='Escrever SARIF em arquivo novo')
        sub.add_argument('--output', help='Escrever JSON em arquivo novo (nunca sobrescreve)')
        sub.add_argument('--format', choices=['json', 'text'], default='json')
    return p


def _save_new(path: str, data: dict) -> None:
    p = Path(path).absolute()
    if p.is_symlink():
        raise InputError('arquivo de saída não pode ser link simbólico')
    payload = json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True).encode('utf-8') + b'\n'
    try:
        descriptor = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        with os.fdopen(descriptor, 'wb') as f:
            f.write(payload)
    except OSError as e:
        raise InputError(f'impossível gravar saída sem sobrescrever: {e}') from e


def _print_text(result: dict) -> None:
    print(f"SudoBoundary {result.get('version', VERSION)} | modo: {result['mode']}")
    if result['mode'] == 'audit':
        print(f"Regras: {result['rules']} | achados: {len(result['findings'])}")
        for f in result['findings']:
            print(f"[{f['severity']}] {f['rule_id']} {f['subject']}: {f['message']}")
    elif result['mode'] == 'compare':
        print(f"Consultas: {result['queries_checked']} | novos achados: {len(result['new_findings'])} | mudanças: {len(result['changes'])}")
        for entry in result['changes']:
            print(f"[{entry['kind']}] consulta {entry['query_index']}: {entry['request']['user']} => {entry['request']['path']}")
    else:
        print(json.dumps(result, ensure_ascii=False, indent=2))


def _compare_findings(report: dict) -> list[dict]:
    issues = list(report['new_findings'])
    for c in report['changes']:
        if c['kind'] == 'access_expanded':
            severity = 'critical' if c['request']['runas'] == 'root' else 'high'
            issues.append(_finding('SB100', severity, 'Nova autorização identificada na matriz de consultas', f"query[{c['query_index']}]", {'request': c['request']}))
        elif c['kind'] == 'controls_weakened':
            issues.append(_finding('SB101', 'high', 'Controles de autorização enfraquecidos', f"query[{c['query_index']}]", {'weakening': c['weakened'], 'request': c['request']}))
    return issues


def main(argv: list[str] | None = None) -> int:
    args = _arguments().parse_args(argv)
    try:
        if args.command == 'compare':
            baseline = validate_policy(load_json(args.baseline))
            candidate = validate_policy(load_json(args.candidate))
            questions = validate_queries(load_json(args.queries))
            report = compare(baseline, candidate, questions)
            findings = _compare_findings(report)
            blocked = gate(findings, args.fail_on)
        else:
            policy = validate_policy(load_json(args.policy))
            if args.command == 'audit':
                report = audit_report(policy)
                findings = report['findings']
                blocked = gate(findings, args.fail_on)
            elif args.command == 'explain':
                req = validate_request(load_json(args.request))
                report = {'tool': 'SudoBoundary', 'version': VERSION, 'mode': 'explain', **evaluate(policy, req)}
                blocked = False
            else:
                queries = validate_queries(load_json(args.queries))
                checks = []
                for i, query in enumerate(queries):
                    req = {k: v for k, v in query.items() if k != 'expected'}
                    actual = evaluate(policy, req)
                    if 'expected' not in query:
                        raise InputError(f'assert requer expected em queries[{i}]')
                    checks.append({'index': i, 'expected': query['expected'], 'actual': actual['allowed'], 'passed': query['expected'] == actual['allowed'], 'deciding_rule_id': actual['deciding_rule_id']})
                report = {'tool': 'SudoBoundary', 'version': VERSION, 'mode': 'assert', 'queries_checked': len(checks), 'passed': sum(c['passed'] for c in checks), 'checks': checks}
                blocked = any(not c['passed'] for c in checks)
        if args.output:
            _save_new(args.output, report)
        if getattr(args, 'sarif', None):
            _save_new(args.sarif, sarif(findings))
        if args.format == 'json':
            print(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False))
        else:
            _print_text(report)
        return 1 if blocked else 0
    except (InputError, TypeError, KeyError, ValueError) as error:
        print(f'SudoBoundary: entrada rejeitada: {error}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
