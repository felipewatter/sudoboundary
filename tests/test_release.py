"""Checks for release reproducibility and archive hygiene."""
import hashlib
import importlib.util
import zipfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class ReleaseTests(unittest.TestCase):
    def test_version_consistency(self):
        import tomllib
        from sudoboundary import __version__
        spec = tomllib.loads((ROOT / 'pyproject.toml').read_text(encoding='utf-8'))
        self.assertEqual(spec['project']['version'], __version__)

    def test_ci_pinned_actions(self):
        import re
        workflow = (ROOT / '.github/workflows/ci.yml').read_text(encoding='utf-8')
        targets = re.findall(r'uses:\s*(actions/[^@\s]+)@([^\s#]+)', workflow)
        self.assertTrue(targets)
        self.assertTrue(all(re.fullmatch(r'[a-f0-9]{40}', ref) for _, ref in targets))
        self.assertIn('contents: read', workflow)
        self.assertIn('contents: write', workflow)

    def test_deterministic_archive(self):
        spec = importlib.util.spec_from_file_location('package', ROOT / 'scripts/package.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        archive, checksum_file = module.make_archive()
        one = hashlib.sha256(archive.read_bytes()).hexdigest()
        archive2, _ = module.make_archive()
        two = hashlib.sha256(archive2.read_bytes()).hexdigest()
        self.assertEqual(one, two)
        self.assertIn(one, checksum_file.read_text(encoding='utf-8'))

    def test_archive_contains_no_secrets(self):
        spec = importlib.util.spec_from_file_location('package', ROOT / 'scripts/package.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        archive, _ = module.make_archive()
        with zipfile.ZipFile(archive) as zf:
            names = zf.namelist()
            self.assertIn('README.md', names)
            self.assertIn('.github/workflows/ci.yml', names)
            self.assertIn('src/sudoboundary/core.py', names)
            self.assertFalse(any('/__pycache__/' in f or f.endswith(('.key', '.pem', '.pyc')) or '/.env' in f for f in names))
            self.assertIsNone(zf.testzip())


if __name__ == '__main__':
    unittest.main()
