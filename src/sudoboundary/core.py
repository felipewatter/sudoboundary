"""Deterministic, offline privileged-command policy regression engine.

This implements a documented JSON *model*, not the complete sudoers grammar.
No subprocess, network operation, or elevated command is used.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any

VERSION = '1.0.0'
MAX_BYTES = 2_000_000
MAX_RULES = 2_000
MAX_REQUESTS = 5_000
MAX_GROUPS = 500
MAX_MEMBERS = 2_000
_IDENT = re.compile(r'^[A-Za-z_][A-Za-z0-9_.-]{0,63}$')
_HOST = re.compile(r'^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$')
_RID = re.compile(r'^[a-z][a-z0-9_-]{0,79}$')
_LEVELS = {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
_RISK_PREFIX = 'SB'
_DEFAULTS = {'authenticate': True, 'env_reset': True, 'secure_path': '/usr/sbin:/usr/bin:/sbin:/bin', 'log_input': True, 'log_output': True, 'noexec': False, 'setenv': False}
_ALLOWED_DEFAULTS = set(_DEFAULTS)
_ALLOWED_TAGS = {'nopasswd', 'setenv', 'log_input', 'log_output', 'noexec'}
_DANGEROUS_INTERPRETERS = {'sh', 'bash', 'dash', 'zsh', 'ksh', 'python', 'python3', 'perl', 'ruby', 'node', 'vim', 'vi', 'less', 'more', 'awk', 'find', 'env'}


class InputError(ValueError):
    """Unsafe, unsupported, or invalid declarative input."""


def _object_pairs(pairs: list[tuple[str, Any]]) -> dict:
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise InputError(f'chave JSON duplicada: {key}')
        obj[key] = value
    return obj


def _reject_constant(value: str) -> None:
    raise InputError(f'constante JSON inválida: {value}')


def _file_path(path: str | Path) -> Path:
    p = Path(path).absolute()
    for component in (p, *p.parents):
        if component.is_symlink():
            raise InputError(f'link simbólico não permitido: {component}')
    return p


def load_json(path: str | Path) -> dict:
    p = _file_path(path)
    try:
        info = p.stat()
        if not stat.S_ISREG(info.st_mode):
            raise InputError(f'arquivo não regular: {p}')
        if info.st_size > MAX_BYTES:
            raise InputError(f'arquivo excede {MAX_BYTES} bytes: {p}')
        flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
        descriptor = os.open(p, flags)
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise InputError('arquivo não regular no momento da leitura')
            with os.fdopen(descriptor, 'rb', closefd=False) as f:
                raw = f.read(MAX_BYTES + 1)
        finally:
            os.close(descriptor)
        if len(raw) > MAX_BYTES:
            raise InputError('limite de tamanho excedido')
        obj = json.loads(raw.decode('utf-8-sig'), object_pairs_hook=_object_pairs, parse_constant=_reject_constant)
        if not isinstance(obj, dict):
            raise InputError('a raiz do JSON deve ser um objeto')
        return obj
    except (OSError, UnicodeError, json.JSONDecodeError) as ex:
        raise InputError(f'falha ao ler JSON: {ex}') from ex


def _keys(obj: Any, allowed: set[str], required: set[str], field: str) -> None:
    if not isinstance(obj, dict):
        raise InputError(f'{field} deve ser objeto')
    if set(obj) - allowed:
        raise InputError(f'{field}: campos desconhecidos: {sorted(set(obj) - allowed)}')
    if required - set(obj):
        raise InputError(f'{field}: campos obrigatórios ausentes: {sorted(required - set(obj))}')


def _text(value: Any, field: str, regex: re.Pattern | None = None) -> str:
    if not isinstance(value, str) or not value or len(value) > 512 or any(ord(x) < 32 for x in value):
        raise InputError(f'{field}: texto inválido')
    if regex and not regex.fullmatch(value):
        raise InputError(f'{field}: identificador inválido: {value!r}')
    return value


def _positive_path(value: Any, field: str) -> str:
    value = _text(value, field)
    if not value.startswith('/') or any(part in ('', '.', '..') for part in value.split('/')[1:]):
        raise InputError(f'{field}: caminho absoluto normalizado obrigatório')
    if any(ch in value for ch in ['*', '?', '[', ']', '\\']):
        raise InputError(f'{field}: padrões de shell não suportados')
    return value


def _strings(value: Any, field: str, regex: re.Pattern, allow_all: bool = True, allow_groups: bool = False) -> list[str]:
    if not isinstance(value, list) or not (1 <= len(value) <= 500):
        raise InputError(f'{field}: lista deve ter entre 1 e 500 elementos')
    out: list[str] = []
    for v in value:
        if v == 'ALL' and allow_all:
            out.append(v)
        elif allow_groups and isinstance(v, str) and v.startswith('%'):
            out.append('%' + _text(v[1:], field, _IDENT))
        else:
            out.append(_text(v, field, regex))
    if len(set(out)) != len(out):
        raise InputError(f'{field}: duplicatas')
    return out


def _bools(obj: dict, allowed: set[str], field: str) -> None:
    _keys(obj, allowed, set(), field)
    for key, val in obj.items():
        if type(val) is not bool:
            raise InputError(f'{field}.{key}: booleano esperado')


def validate_policy(policy: dict) -> dict:
    _keys(policy, {'schema_version', 'defaults', 'groups', 'rules'}, {'schema_version', 'rules'}, 'policy')
    if type(policy['schema_version']) is not int or policy['schema_version'] != 1:
        raise InputError('schema_version suportado: 1')
    defaults = policy.get('defaults', {})
    _keys(defaults, _ALLOWED_DEFAULTS, set(), 'defaults')
    for key, value in defaults.items():
        if key == 'secure_path':
            if value is not None:
                _text(value, key)
                if any(not p.startswith('/') or p in ('', '/', '.') for p in value.split(':')):
                    raise InputError('secure_path deve conter apenas caminhos absolutos')
        elif type(value) is not bool:
            raise InputError(f'defaults.{key} deve ser booleano')
    groups = policy.get('groups', {})
    if not isinstance(groups, dict) or len(groups) > MAX_GROUPS:
        raise InputError('groups deve ser um objeto com no máximo 500 grupos')
    for group, members in groups.items():
        _text(group, 'groups.key', _IDENT)
        if not isinstance(members, list) or len(members) > MAX_MEMBERS:
            raise InputError(f'grupo {group}: membros inválidos')
        for member in members:
            _text(member, f'groups.{group}', _IDENT)
        if len(members) != len(set(members)):
            raise InputError(f'grupo {group}: duplicatas')
    rules = policy['rules']
    if not isinstance(rules, list) or len(rules) > MAX_RULES:
        raise InputError('rules deve ser lista com no máximo 2000 regras')
    seen: set[str] = set()
    for ix, rule in enumerate(rules):
        fld = f'rules[{ix}]'
        _keys(rule, {'id', 'users', 'hosts', 'runas', 'commands', 'effect', 'tags', 'reason'}, {'id', 'users', 'hosts', 'runas', 'commands', 'effect'}, fld)
        identifier = _text(rule['id'], f'{fld}.id', _RID)
        if identifier in seen:
            raise InputError(f'id duplicado: {identifier}')
        seen.add(identifier)
        users = _strings(rule['users'], f'{fld}.users', _IDENT, allow_groups=True)
        for item in users:
            if item.startswith('%') and item[1:] not in groups:
                raise InputError(f'{fld}: grupo não declarado: {item}')
        _strings(rule['hosts'], f'{fld}.hosts', _HOST)
        _strings(rule['runas'], f'{fld}.runas', _IDENT)
        if rule['effect'] not in ('allow', 'deny'):
            raise InputError(f'{fld}: effect deve ser allow ou deny')
        cmds = rule['commands']
        if not isinstance(cmds, list) or not 1 <= len(cmds) <= 100:
            raise InputError(f'{fld}: commands deve conter de 1 a 100 comandos')
        for ci, cmd in enumerate(cmds):
            _keys(cmd, {'path', 'argv'}, {'path', 'argv'}, f'{fld}.commands[{ci}]')
            if cmd['path'] != 'ALL':
                _positive_path(cmd['path'], f'{fld}.commands[{ci}].path')
            argv = cmd['argv']
            if argv is not None:
                if not isinstance(argv, list) or len(argv) > 64:
                    raise InputError(f'{fld}: argv deve ser lista de até 64 argumentos ou null')
                for arg in argv:
                    _text(arg, f'{fld}.argv')
        tags = rule.get('tags', {})
        _bools(tags, _ALLOWED_TAGS, f'{fld}.tags')
        if 'reason' in rule:
            _text(rule['reason'], f'{fld}.reason')
    return policy


def validate_request(req: dict, expected_allowed: bool = False) -> dict:
    allowed = {'user', 'host', 'runas', 'path', 'argv'} | ({'expected'} if expected_allowed else set())
    _keys(req, allowed, {'user', 'host', 'runas', 'path', 'argv'}, 'request')
    _text(req['user'], 'user', _IDENT)
    _text(req['host'], 'host', _HOST)
    _text(req['runas'], 'runas', _IDENT)
    _positive_path(req['path'], 'request.path')
    if not isinstance(req['argv'], list) or len(req['argv']) > 64:
        raise InputError('request.argv deve ser lista com até 64 elementos')
    for arg in req['argv']:
        _text(arg, 'request.argv')
    if 'expected' in req and (not expected_allowed or type(req['expected']) is not bool):
        raise InputError('request.expected deve ser booleano')
    return req


def validate_queries(obj: dict) -> list[dict]:
    _keys(obj, {'schema_version', 'queries'}, {'schema_version', 'queries'}, 'queries')
    if type(obj['schema_version']) is not int or obj['schema_version'] != 1:
        raise InputError('queries.schema_version deve ser 1')
    qs = obj['queries']
    if not isinstance(qs, list) or not 1 <= len(qs) <= MAX_REQUESTS:
        raise InputError('queries deve ter entre 1 e 5000 entradas')
    for q in qs:
        validate_request(q, expected_allowed=True)
    return qs


def _match_item(values: list[str], target: str) -> bool:
    return 'ALL' in values or target in values


def _match_rule(rule: dict, req: dict, groups: dict) -> bool:
    user = req['user']
    users = rule['users']
    if not (_match_item(users, user) or any(user in members for group, members in groups.items() if f'%{group}' in users)):
        return False
    if not _match_item(rule['hosts'], req['host']) or not _match_item(rule['runas'], req['runas']):
        return False
    for cmd in rule['commands']:
        if cmd['path'] in ('ALL', req['path']) and (cmd['argv'] is None or cmd['argv'] == req['argv']):
            return True
    return False


def effective_tags(policy: dict, rule: dict | None = None) -> dict:
    d = {**_DEFAULTS, **policy.get('defaults', {})}
    flags = {'nopasswd': not d['authenticate'], 'setenv': d['setenv'], 'log_input': d['log_input'], 'log_output': d['log_output'], 'noexec': d['noexec']}
    if rule:
        flags.update(rule.get('tags', {}))
    return flags


def evaluate(policy: dict, req: dict) -> dict:
    """Last matching rule wins in the declared model. No sudoers inference."""
    validate_request(req)
    matches = [r for r in policy['rules'] if _match_rule(r, req, policy.get('groups', {}))]
    last = matches[-1] if matches else None
    return {'allowed': bool(last and last['effect'] == 'allow'), 'matched_rule_ids': [r['id'] for r in matches], 'deciding_rule_id': last['id'] if last else None, 'effect': last['effect'] if last else 'implicit_deny', 'tags': effective_tags(policy, last) if last and last['effect'] == 'allow' else None, 'request': req}


def _finding(code: str, severity: str, message: str, subject: str, evidence: dict | None = None) -> dict:
    basis = {'rule': code, 'subject': subject, 'evidence': evidence or {}}
    fp = hashlib.sha256(json.dumps(basis, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()).hexdigest()[:20]
    return {'rule_id': code, 'severity': severity, 'message': message, 'subject': subject, 'evidence': evidence or {}, 'fingerprint': fp}


def audit(policy: dict) -> list[dict]:
    findings: list[dict] = []
    defaults = {**_DEFAULTS, **policy.get('defaults', {})}
    if not defaults['env_reset']:
        findings.append(_finding('SB008', 'high', 'env_reset desativado no modelo', 'defaults.env_reset'))
    if defaults['secure_path'] is None:
        findings.append(_finding('SB009', 'medium', 'secure_path ausente no modelo', 'defaults.secure_path'))
    for rule in policy['rules']:
        if rule['effect'] != 'allow':
            continue
        ident = rule['id']
        tags = effective_tags(policy, rule)
        root = _match_item(rule['runas'], 'root')
        cmd_all = any(x['path'] == 'ALL' for x in rule['commands'])
        if cmd_all and root:
            findings.append(_finding('SB001', 'critical', 'Execução de qualquer comando como root', ident))
        if root and 'ALL' in rule['users']:
            findings.append(_finding('SB002', 'critical', 'Qualquer usuário pode executar como root', ident))
        if root and tags['nopasswd']:
            findings.append(_finding('SB003', 'high', 'Acesso privilegiado sem autenticação', ident))
        if root and tags['setenv']:
            findings.append(_finding('SB004', 'high', 'Ambiente arbitrário permitido para execução como root', ident))
        if root and any(x['path'].split('/')[-1] in _DANGEROUS_INTERPRETERS for x in rule['commands']):
            findings.append(_finding('SB005', 'high', 'Interpretador ou utilitário com capacidade de comandos sob root', ident))
        if root and any(x['argv'] is None and x['path'] != 'ALL' for x in rule['commands']):
            findings.append(_finding('SB006', 'medium', 'Argumentos irrestritos para comando root', ident))
        if root and (not tags['log_input'] or not tags['log_output']):
            findings.append(_finding('SB007', 'medium', 'Auditoria de entrada/saída incompleta', ident))
        if root and 'ALL' in rule['hosts']:
            findings.append(_finding('SB010', 'low', 'Regra root aplicada a todos os hosts no modelo', ident))
        if root and any(x['path'] == 'ALL' and x['argv'] is not None for x in rule['commands']):
            findings.append(_finding('SB011', 'medium', 'Caminho de comando irrestrito', ident))
    return sorted(findings, key=lambda f: (-_LEVELS[f['severity']], f['rule_id'], f['subject']))


def fingerprint(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode('utf-8')).hexdigest()


def audit_report(policy: dict) -> dict:
    findings = audit(policy)
    return {'tool': 'SudoBoundary', 'version': VERSION, 'mode': 'audit', 'model_sha256': fingerprint(policy), 'rules': len(policy['rules']), 'findings': findings, 'counts': {level: sum(f['severity'] == level for f in findings) for level in _LEVELS}}


def compare(baseline: dict, candidate: dict, queries: list[dict]) -> dict:
    before = {f['fingerprint']: f for f in audit(baseline)}
    after = {f['fingerprint']: f for f in audit(candidate)}
    new = sorted((f for key, f in after.items() if key not in before), key=lambda f: (-_LEVELS[f['severity']], f['rule_id'], f['subject']))
    resolved = sorted((f for key, f in before.items() if key not in after), key=lambda f: (f['rule_id'], f['subject']))
    changes = []
    for i, req in enumerate(queries):
        only_req = {k: v for k, v in req.items() if k != 'expected'}
        old = evaluate(baseline, only_req)
        fresh = evaluate(candidate, only_req)
        if old['allowed'] != fresh['allowed']:
            direction = 'access_expanded' if fresh['allowed'] else 'access_removed'
            changes.append({'query_index': i, 'kind': direction, 'request': only_req, 'before': old, 'after': fresh})
        elif old['allowed'] and fresh['allowed']:
            old_tags, new_tags = old['tags'], fresh['tags']
            weakened = [tag for tag in ('nopasswd', 'setenv') if not old_tags[tag] and new_tags[tag]]
            weakened += [tag for tag in ('log_input', 'log_output', 'noexec') if old_tags[tag] and not new_tags[tag]]
            if weakened:
                changes.append({'query_index': i, 'kind': 'controls_weakened', 'weakened': weakened, 'request': only_req, 'before': old, 'after': fresh})
    return {'tool': 'SudoBoundary', 'version': VERSION, 'mode': 'compare', 'baseline_sha256': fingerprint(baseline), 'candidate_sha256': fingerprint(candidate), 'queries_checked': len(queries), 'new_findings': new, 'resolved_findings': resolved, 'changes': changes}


def sarif(findings: list[dict]) -> dict:
    rule_ids = sorted({f['rule_id'] for f in findings})
    return {'version': '2.1.0', '$schema': 'https://json.schemastore.org/sarif-2.1.0.json', 'runs': [{'tool': {'driver': {'name': 'SudoBoundary', 'version': VERSION, 'rules': [{'id': r, 'shortDescription': {'text': r}} for r in rule_ids]}}, 'results': [{'ruleId': f['rule_id'], 'level': {'critical': 'error', 'high': 'error', 'medium': 'warning', 'low': 'note', 'info': 'note'}[f['severity']], 'message': {'text': f['message']}, 'partialFingerprints': {'primaryLocationLineHash': f['fingerprint']}, 'properties': {'subject': f['subject'], 'severity': f['severity']}} for f in findings]}]}


def gate(findings: list[dict], threshold: str) -> bool:
    if threshold == 'none':
        return False
    if threshold not in _LEVELS:
        raise InputError(f'limiar inválido: {threshold}')
    return any(_LEVELS[x['severity']] >= _LEVELS[threshold] for x in findings)
