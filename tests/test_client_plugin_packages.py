# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0
"""Exercise distributable client packages and their shared remote tool contract."""

import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from zipfile import ZipFile

import pytest
from mcp import Client

from vt_mcp.server import create_report_server

ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / "scripts/build_client_plugins.py"
spec = importlib.util.spec_from_file_location("build_client_plugins", BUILDER)
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)

PLUGIN_FILES = {
    "grok-build": {
        ".grok-plugin/plugin.json",
        ".mcp.json",
        "README.md",
        "skills/threat-intelligence/SKILL.md",
    },
    "kimi": {"kimi.plugin.json", "README.md", "skills/threat-intelligence/SKILL.md"},
}
LICENSE_FILES = {"LICENSE", "NOTICE", "LICENSES/MIT.txt"}


def source_copy(tmp_path):
    root = tmp_path / "source"
    for client in PLUGIN_FILES:
        shutil.copytree(ROOT / "plugins" / client, root / "plugins" / client)
    for name in LICENSE_FILES:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, path)
    return root


def test_cli_archives_have_native_root_layout_exact_source_bytes_and_checksums(tmp_path):
    subprocess.run(
        [sys.executable, str(BUILDER), "--output-dir", str(tmp_path)],
        check=True,
        capture_output=True,
    )
    checksums = dict(
        reversed(line.split()) for line in (tmp_path / "SHA256SUMS").read_text().splitlines()
    )
    assert len(checksums) == 2
    for client, files in PLUGIN_FILES.items():
        artifact = tmp_path / f"virustotal-{client}-0.1.0.zip"
        assert checksums[artifact.name] == hashlib.sha256(artifact.read_bytes()).hexdigest()
        with ZipFile(artifact) as archive:
            assert set(archive.namelist()) == files | LICENSE_FILES
            assert archive.testzip() is None
            for name in files:
                assert archive.read(name) == (ROOT / "plugins" / client / name).read_bytes()
            for name in LICENSE_FILES:
                assert archive.read(name) == (ROOT / name).read_bytes()
            # Kimi's installer needs the manifest at the ZIP root, not plugins/kimi/.
            if client == "kimi":
                assert json.loads(archive.read("kimi.plugin.json"))["name"] == "virustotal"


@pytest.mark.parametrize("client", PLUGIN_FILES)
def test_archives_ignore_local_extras_permissions_and_timestamps(tmp_path, client):
    root = source_copy(tmp_path)
    first = builder.build_plugin(root, client, tmp_path / "first").read_bytes()
    plugin = root / "plugins" / client
    # An untracked local file must never leak into a public package.
    (plugin / ".env").write_text("SYNTHETIC_LOCAL_VALUE=not-for-distribution\n")
    (plugin / "hooks").mkdir()
    (plugin / "hooks/hooks.json").write_text('{"synthetic": true}')
    for path in root.rglob("*"):
        if path.is_file():
            os.utime(path, (2_000_000_000, 2_000_000_000))
            path.chmod(0o600)
    second = builder.build_plugin(root, client, tmp_path / "second").read_bytes()
    assert first == second


@pytest.mark.parametrize("invalid", ["missing", "linked_file", "linked_directory"])
def test_incomplete_or_linked_source_is_rejected_before_writing_archive(tmp_path, invalid):
    root = source_copy(tmp_path)
    plugin = root / "plugins/kimi"
    if invalid == "linked_directory":
        shutil.move(str(plugin / "skills"), str(tmp_path / "outside"))
        (plugin / "skills").symlink_to(tmp_path / "outside", target_is_directory=True)
    else:
        (plugin / "README.md").unlink()
        if invalid == "linked_file":
            (plugin / "README.md").symlink_to(ROOT / "README.md")
    output = tmp_path / "output"
    with pytest.raises(ValueError, match="Package input"):
        builder.build_plugin(root, "kimi", output)
    assert not output.exists()


@pytest.mark.parametrize("client", PLUGIN_FILES)
def test_remote_only_manifest_and_submission_policy_match_existing_plugin(client):
    plugin = ROOT / "plugins" / client
    if client == "grok-build":
        config = json.loads((plugin / ".mcp.json").read_text())
        assert config == {
            "mcpServers": {"virustotal": {"type": "http", "url": "https://ai.virustotal.com/mcp"}}
        }
        manifest = json.loads((plugin / ".grok-plugin/plugin.json").read_text())
    else:
        manifest = json.loads((plugin / "kimi.plugin.json").read_text())
        assert manifest["mcpServers"] == {"virustotal": {"url": "https://ai.virustotal.com/mcp"}}
        assert manifest["skills"] == "./skills/"
    assert manifest["name"] == "virustotal"
    assert manifest["license"] == "Apache-2.0"
    assert not {"hooks", "agents", "commands", "systemPrompt"} & manifest.keys()
    assert {p.relative_to(plugin).as_posix() for p in plugin.rglob("*") if p.is_file()} == (
        PLUGIN_FILES[client]
    )

    # Client authentication differs; the upload, interpretation and recovery policy must not.
    policy_start = "URL queries disclose the complete URL"
    canonical = (ROOT / "plugins/antigravity/skills/threat-intelligence/SKILL.md").read_text()
    skill = (plugin / "skills/threat-intelligence/SKILL.md").read_text()
    assert skill[skill.index(policy_start) :] == canonical[canonical.index(policy_start) :]


@pytest.mark.anyio
async def test_readmes_describe_all_remote_tools_without_binding_or_dispatching():
    @asynccontextmanager
    async def lifespan(_):
        yield None

    def forbidden(_):
        pytest.fail("Catalog discovery must not bind a reader or dispatch an operation")

    server = create_report_server(
        lifespan=lifespan,
        bind_reports=forbidden,
        bind_submissions=forbidden,
        bind_analyses=forbidden,
        bind_network_submissions=forbidden,
        bind_attachment_submissions=forbidden,
    )
    async with Client(server, mode="legacy") as client:
        names = {tool.name for tool in (await client.list_tools()).tools}
    assert len(names) == 11
    for plugin in PLUGIN_FILES:
        readme = (ROOT / "plugins" / plugin / "README.md").read_text()
        inventory = readme.split("## Tools and safety", 1)[1].split("## Files", 1)[0]
        assert set(re.findall(r"`((?:get_|submit_|reanalyze_)\w+)`", inventory)) == names
