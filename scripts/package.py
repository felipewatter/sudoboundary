"""Deterministic release ZIP and checksum, without using external dependencies."""
from __future__ import annotations

import hashlib
import os
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION = 'v1.0.0'
EXCLUDE = {'.git', '.venv', '__pycache__', '.pytest_cache', '.ruff_cache', 'dist', 'build', '.mypy_cache'}


def make_archive() -> tuple[Path, Path]:
    dest = ROOT / 'dist'
    dest.mkdir(exist_ok=True)
    archive = dest / f'sudoboundary-{VERSION}-source.zip'
    paths = []
    for path in ROOT.rglob('*'):
        if not path.is_file() or any(part in EXCLUDE or part.endswith('.egg-info') for part in path.relative_to(ROOT).parts):
            continue
        if path.is_symlink() or any(part.is_symlink() for part in path.parents if part != ROOT.parent):
            raise SystemExit(f'Link simbólico detectado: {path}')
        if path.suffix in {'.pem', '.key', '.pyc'} or path.name.endswith('.egg-info'):
            raise SystemExit(f'Arquivo proibido no pacote: {path}')
        if path.name.startswith('.env'):
            raise SystemExit(f'Arquivo .env proibido: {path}')
        paths.append(path)
    with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for path in sorted(paths, key=lambda p: p.as_posix()):
            arc = path.relative_to(ROOT).as_posix()
            info = zipfile.ZipInfo(arc, (1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (0o100644 & 0xffff) << 16
            zf.writestr(info, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    manifest = dest / (archive.name + '.sha256')
    manifest.write_text(f'{digest}  {archive.name}\n', encoding='utf8')
    print(f'Pacote: {archive.name}, arquivos: {len(paths)}, bytes: {archive.stat().st_size}')
    print('SHA-256:', digest)
    return archive, manifest


if __name__ == '__main__':
    make_archive()
