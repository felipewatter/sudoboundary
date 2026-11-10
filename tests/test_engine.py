"""Regression and adversarial tests for the offline policy model."""
import copy
import json
import os
import tempfile
import unittest
from pathlib import Path

from sudoboundary.core import (
    InputError, _finding, audit, audit_report, compare, effective_tags,
    evaluate, fingerprint, gate, load_json, sarif, validate_policy,
    validate_queries, validate_request,
)

BASE = {'schema_version': 1, 'groups': {'ops': ['ana', 'bruno']}, 'rules': [
    {'id': 'allow-status', 'users': ['%ops'], 'hosts': ['web-01'],
     'runas': ['root'], 'commands': [{'path': '/usr/bin/systemctl', 'argv': ['status', 'nginx']}],
     'effect': 'allow', 'tags': {'noexec': True, 'log_input': True, 'log_output': True}},
]}
REQ = {'user': 'ana', 'host': 'web-01', 'runas': 'root',
       'path': '/usr/bin/systemctl', 'argv': ['status', 'nginx']}


def model():
    return validate_policy(copy.deepcopy(BASE))


def request(**kwargs):
    return {**REQ, **kwargs}


def additional(rule_id='deny', **overrides):
    return {**copy.deepcopy(BASE['rules'][0]), 'id': rule_id, **overrides}


class ValidationTests(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(1, model()['schema_version'])

    def test_unknown_top_level(self):
        with self.assertRaises(InputError): validate_policy({**model(), 'cmd': 'x'})

    def test_wrong_schema(self):
        p = model(); p['schema_version'] = 2
        with self.assertRaises(InputError): validate_policy(p)

    def test_boolean_schema_rejected(self):
        p = model(); p['schema_version'] = True
        with self.assertRaises(InputError): validate_policy(p)

    def test_duplicate_rule_id(self):
        p = model(); p['rules'].append(copy.deepcopy(p['rules'][0]))
        with self.assertRaises(InputError): validate_policy(p)

    def test_group_unknown(self):
        p = model(); p['rules'][0]['users'] = ['%missing']
        with self.assertRaises(InputError): validate_policy(p)

    def test_group_members_invalid(self):
        p = model(); p['groups']['ops'] = [12]
        with self.assertRaises(InputError): validate_policy(p)

    def test_group_members_duplicates(self):
        p = model(); p['groups']['ops'] = ['ana', 'ana']
        with self.assertRaises(InputError): validate_policy(p)

    def test_unknown_tag(self):
        p = model(); p['rules'][0]['tags']['unrestricted'] = True
        with self.assertRaises(InputError): validate_policy(p)

    def test_tags_are_boolean(self):
        p = model(); p['rules'][0]['tags']['noexec'] = 'true'
        with self.assertRaises(InputError): validate_policy(p)

    def test_path_traversal(self):
        p = model(); p['rules'][0]['commands'][0]['path'] = '/bin/../bin/sh'
        with self.assertRaises(InputError): validate_policy(p)

    def test_relative_path(self):
        p = model(); p['rules'][0]['commands'][0]['path'] = 'systemctl'
        with self.assertRaises(InputError): validate_policy(p)

    def test_glob_path(self):
        p = model(); p['rules'][0]['commands'][0]['path'] = '/bin/*'
        with self.assertRaises(InputError): validate_policy(p)

    def test_empty_arg(self):
        p = model(); p['rules'][0]['commands'][0]['argv'] = ['']
        with self.assertRaises(InputError): validate_policy(p)

    def test_duplicate_groups_selector(self):
        p = model(); p['rules'][0]['users'] = ['%ops', '%ops']
        with self.assertRaises(InputError): validate_policy(p)

    def test_too_many_rules(self):
        p = model(); p['rules'] = [p['rules'][0]] * 2001
        with self.assertRaises(InputError): validate_policy(p)

    def test_unknown_request_key(self):
        with self.assertRaises(InputError): validate_request(request(typo=True))

    def test_expected_disallowed_in_explain(self):
        with self.assertRaises(InputError): validate_request(request(expected=True))

    def test_query_expected_bool(self):
        with self.assertRaises(InputError): validate_queries({'schema_version': 1, 'queries': [request(expected=1)]})

    def test_missing_query(self):
        with self.assertRaises(InputError): validate_queries({'schema_version': 1, 'queries': []})

    def test_root_json_duplicate_key(self):
        with tempfile.TemporaryDirectory() as temp:
            f = Path(temp) / 'a.json'; f.write_text('{"a":1,"a":2}', encoding='utf8')
            with self.assertRaises(InputError): load_json(f)

    def test_nested_duplicate_key(self):
        with tempfile.TemporaryDirectory() as temp:
            f = Path(temp) / 'a.json'; f.write_text('{"a":{"x":1,"x":2}}', encoding='utf8')
            with self.assertRaises(InputError): load_json(f)

    def test_nan_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            f = Path(temp) / 'a.json'; f.write_text('{"a":NaN}', encoding='utf8')
            with self.assertRaises(InputError): load_json(f)

    def test_large_file_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            f = Path(temp) / 'a.json'; f.write_bytes(b'0' * 2_000_001)
            with self.assertRaises(InputError): load_json(f)

    def test_directory_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(InputError): load_json(temp)

    def test_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            real = Path(temp) / 'real.json'; real.write_text('{}')
            link = Path(temp) / 'link.json'
            try: link.symlink_to(real)
            except (NotImplementedError, OSError): self.skipTest('links simbólicos indisponíveis')
            with self.assertRaises(InputError): load_json(link)

    def test_non_object_json(self):
        with tempfile.TemporaryDirectory() as temp:
            f = Path(temp) / 'x'; f.write_text('[]')
            with self.assertRaises(InputError): load_json(f)

    def test_defaults_path(self):
        p = model(); p['defaults'] = {'secure_path': 'relative'}
        with self.assertRaises(InputError): validate_policy(p)


class EvaluationTests(unittest.TestCase):
    def test_allowed_group_member(self):
        self.assertTrue(evaluate(model(), REQ)['allowed'])

    def test_denied_other_group_member(self):
        self.assertFalse(evaluate(model(), request(user='outsider'))['allowed'])

    def test_denied_other_host(self):
        self.assertFalse(evaluate(model(), request(host='db-02'))['allowed'])

    def test_denied_other_runas(self):
        self.assertFalse(evaluate(model(), request(runas='postgres'))['allowed'])

    def test_denied_other_args(self):
        self.assertFalse(evaluate(model(), request(argv=['restart', 'nginx']))['allowed'])

    def test_denied_other_path(self):
        self.assertFalse(evaluate(model(), request(path='/bin/sh'))['allowed'])

    def test_last_match_deny(self):
        p = model(); p['rules'].append(additional('deny-later', effect='deny'))
        self.assertFalse(evaluate(validate_policy(p), REQ)['allowed'])
        self.assertEqual(['allow-status', 'deny-later'], evaluate(p, REQ)['matched_rule_ids'])

    def test_last_match_allow(self):
        p = model(); p['rules'].insert(0, additional('deny-first', effect='deny'))
        self.assertTrue(evaluate(validate_policy(p), REQ)['allowed'])

    def test_wildcard_path_and_argv(self):
        p = model(); p['rules'][0]['commands'] = [{'path': 'ALL', 'argv': None}]
        self.assertTrue(evaluate(validate_policy(p), request(path='/bin/sh', argv=['-c', 'echo hi']))['allowed'])

    def test_any_args_only_exact_command(self):
        p = model(); p['rules'][0]['commands'][0]['argv'] = None
        self.assertTrue(evaluate(validate_policy(p), request(argv=['restart', 'nginx']))['allowed'])
        self.assertFalse(evaluate(p, request(path='/bin/sh'))['allowed'])

    def test_exact_no_args(self):
        p = model(); p['rules'][0]['commands'][0]['argv'] = []
        self.assertTrue(evaluate(validate_policy(p), request(argv=[]))['allowed'])
        self.assertFalse(evaluate(p, REQ)['allowed'])

    def test_default_tags(self):
        self.assertFalse(effective_tags(model())['nopasswd'])

    def test_implicit_deny_has_no_tags(self):
        decision = evaluate(model(), request(user='nope'))
        self.assertIsNone(decision['tags'])
        self.assertEqual('implicit_deny', decision['effect'])


class RiskTests(unittest.TestCase):
    def test_minimal_has_no_high_risks(self):
        self.assertFalse(gate(audit(model()), 'high'))

    def test_any_root_critical(self):
        p = model(); p['rules'][0]['commands'] = [{'path': 'ALL', 'argv': None}]
        self.assertIn('SB001', [f['rule_id'] for f in audit(validate_policy(p))])

    def test_everyone_as_root_critical(self):
        p = model(); p['rules'][0]['users'] = ['ALL']
        self.assertIn('SB002', [f['rule_id'] for f in audit(validate_policy(p))])

    def test_nopasswd_high(self):
        p = model(); p['rules'][0]['tags']['nopasswd'] = True
        self.assertIn('SB003', [f['rule_id'] for f in audit(validate_policy(p))])

    def test_setenv_high(self):
        p = model(); p['rules'][0]['tags']['setenv'] = True
        self.assertIn('SB004', [f['rule_id'] for f in audit(validate_policy(p))])

    def test_shell_high(self):
        p = model(); p['rules'][0]['commands'] = [{'path': '/bin/bash', 'argv': []}]
        self.assertIn('SB005', [f['rule_id'] for f in audit(validate_policy(p))])

    def test_argv_any_medium(self):
        p = model(); p['rules'][0]['commands'][0]['argv'] = None
        self.assertIn('SB006', [f['rule_id'] for f in audit(validate_policy(p))])

    def test_logging_medium(self):
        p = model(); p['rules'][0]['tags']['log_output'] = False
        self.assertIn('SB007', [f['rule_id'] for f in audit(validate_policy(p))])

    def test_env_reset_high(self):
        p = model(); p['defaults'] = {'env_reset': False}
        self.assertIn('SB008', [f['rule_id'] for f in audit(validate_policy(p))])

    def test_missing_path_medium(self):
        p = model(); p['defaults'] = {'secure_path': None}
        self.assertIn('SB009', [f['rule_id'] for f in audit(validate_policy(p))])

    def test_sha_stable_across_key_order(self):
        self.assertEqual(fingerprint({'a': 1, 'b': 2}), fingerprint({'b': 2, 'a': 1}))

    def test_sarif_format(self):
        result = sarif(audit(model()))
        self.assertEqual('2.1.0', result['version'])
        self.assertEqual('SudoBoundary', result['runs'][0]['tool']['driver']['name'])

    def test_gate_none(self):
        p = model(); p['rules'][0]['tags']['nopasswd'] = True
        self.assertFalse(gate(audit(validate_policy(p)), 'none'))


class ComparisonTests(unittest.TestCase):
    def test_access_expansion(self):
        p = model(); p['rules'][0]['commands'][0]['argv'] = None
        report = compare(model(), validate_policy(p), [request(argv=['restart', 'nginx'])])
        self.assertEqual('access_expanded', report['changes'][0]['kind'])

    def test_access_removed(self):
        p = model(); p['rules'][0]['effect'] = 'deny'
        report = compare(model(), validate_policy(p), [REQ])
        self.assertEqual('access_removed', report['changes'][0]['kind'])

    def test_control_weakened(self):
        p = model(); p['rules'][0]['tags']['noexec'] = False
        report = compare(model(), validate_policy(p), [REQ])
        self.assertEqual(['noexec'], report['changes'][0]['weakened'])

    def test_nopasswd_weakening(self):
        p = model(); p['rules'][0]['tags']['nopasswd'] = True
        self.assertEqual(['nopasswd'], compare(model(), validate_policy(p), [REQ])['changes'][0]['weakened'])

    def test_new_findings_detected(self):
        p = model(); p['rules'][0]['tags']['setenv'] = True
        self.assertTrue(any(f['rule_id'] == 'SB004' for f in compare(model(), validate_policy(p), [REQ])['new_findings']))

    def test_resolved_findings(self):
        p = model(); p['rules'][0]['tags']['setenv'] = True
        report = compare(validate_policy(p), model(), [REQ])
        self.assertIn('SB004', [f['rule_id'] for f in report['resolved_findings']])

    def test_group_membership_regression(self):
        p = model(); p['groups']['ops'].append('carla')
        report = compare(model(), validate_policy(p), [request(user='carla')])
        self.assertEqual('access_expanded', report['changes'][0]['kind'])

    def test_deterministic_reporting(self):
        self.assertEqual(audit_report(model()), audit_report(model()))


if __name__ == '__main__': unittest.main()
