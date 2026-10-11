# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0
"""Build reproducible Grok Build and Kimi plugin ZIPs without runtime dependencies.

Only the enumerated plugin files and repository license notices enter the ZIP.
The native manifest is at the archive root; no enclosing repository directory is
included. Fixed metadata and uncompressed entries keep bytes stable across hosts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
from pathlib import Path
from zipfile import ZIP_STORED, ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
MANIFESTS = {
    "grok-build": ".grok-plugin/plugin.json",
    "kimi": "kimi.plugin.json",
}
COMMON_FILES = ("README.md", "skills/threat-intelligence/SKILL.md")
LICENSE_FILES = ("LICENSE", "NOTICE", "LICENSES/MIT.txt")


def read_file(root: Path, relative: str) -> bytes:
    """Refuse links, including linked parent directories, in package inputs."""
    path = root
    for part in Path(relative).parts:
        path = path / part
        if path.is_symlink():
            raise ValueError(f"Package input must not be a symlink: {relative}")
    if not path.is_file():
        raise ValueError(f"Package input is not a file: {relative}")
    return path.read_bytes()


def build_plugin(root: Path, client: str, output: Path) -> Path:
    """Build one client archive, returning its path."""
    manifest_path = MANIFESTS[client]
    plugin_prefix = f"plugins/{client}/"
    manifest = json.loads(read_file(root, plugin_prefix + manifest_path))
    version = manifest.get("version", "")
    if manifest.get("name") != "virustotal" or not isinstance(version, str):
        raise ValueError("Expected a VirusTotal plugin with a string version")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError("Plugin version must be a stable major.minor.patch version")

    names = (manifest_path, *COMMON_FILES)
    if client == "grok-build":
        names += (".mcp.json",)
    contents = {name: read_file(root, plugin_prefix + name) for name in names}
    contents.update({name: read_file(root, name) for name in LICENSE_FILES})

    output.mkdir(parents=True, exist_ok=True)
    destination = output / f"virustotal-{client}-{version}.zip"
    with ZipFile(destination, "w", compression=ZIP_STORED) as archive:
        for name, data in sorted(contents.items()):
            entry = ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            entry.create_system = 3
            entry.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(entry, data)
    return destination


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client", choices=[*MANIFESTS, "all"], default="all")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "dist/client-plugins")
    args = parser.parse_args()
    clients = tuple(MANIFESTS) if args.client == "all" else (args.client,)
    artifacts = [build_plugin(ROOT, client, args.output_dir) for client in clients]
    checksums = "".join(
        f"{hashlib.sha256(artifact.read_bytes()).hexdigest()}  {artifact.name}\n"
        for artifact in sorted(artifacts)
    )
    (args.output_dir / "SHA256SUMS").write_text(checksums, encoding="utf-8", newline="\n")
    print(checksums, end="")


if __name__ == "__main__":
    main()
