/**
 * Copyright 2026 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 *
 * VirusTotal for DeepSeek Harness — Host half.
 *
 * Two contributions, both from this one bundle:
 *
 *   1. The bundled `virustotal-threat-intelligence` skill, so that installing
 *      the bundle delivers the tools and their operating guidance together, as
 *      the other client plugins in this repository do.
 *   2. `virustotal_submit_local_file`, which performs the byte transfer that the
 *      hosted server cannot do on its own.
 *
 * The connection itself belongs to `@deepseek-ai/dsh-mcp-client`, inserted by
 * this bundle's patch.
 *
 * This module intentionally imports nothing from `@deepseek-ai/*`. A bundle
 * installed into a profile resolves modules from its own real path, not from the
 * Harness installation, so those specifiers are not resolvable here; the tool
 * definition below is therefore a plain registry definition with raw JSON Schema
 * rather than one built by the shipped `defineTool` helper.
 */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { basename } from 'node:path';
import { fileURLToPath } from 'node:url';

const SKILL_DIRECTORY = new URL('./skills/virustotal-threat-intelligence/', import.meta.url);
const SKILL_FILE = new URL('SKILL.md', SKILL_DIRECTORY);

/** The hosted server's decoded-content limit, and the tool's own byte cap. */
const MAX_BYTES = 24_000_000;

/** The connected submission tool this wrapper delegates to. */
const SUBMIT_TOOL = 'mcp__virustotal__submit_file';

/**
 * Filenames that are refused before any read.
 *
 * This mirrors `credential_filename_pattern` in
 * `plugins/claude-code/client-contracts.json`, kept inline so the bundle stays
 * self-contained wherever it is installed from. It is a filename check, not a
 * content-based secret detector.
 */
const CREDENTIAL_FILENAME =
  /^(?:\.env.*|id_(?:rsa|dsa|ecdsa|ed25519|xmss).*|ssh_host_.*_key.*|\.netrc|\.npmrc|\.pypirc|\.git-credentials|\.pgpass|\.htpasswd|credentials.*|kubeconfig)$|\.(?:pem|key|kdbx|p12|pfx|ppk|jks|keystore)$/i;

/** Cordis plugin name, referenced by this bundle's patch row id. */
const name = 'virustotal-skill';

/** The registries this plugin contributes to. */
const inject = ['skills', 'tools', 'fs'];

/**
 * Read the leading YAML frontmatter of a SKILL.md file.
 *
 * Only the flat `key: value` form these skills actually use is supported. A
 * malformed block is reported rather than silently degraded, because a skill
 * without a description is never invoked.
 */
function readFrontmatter(source) {
  const block = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?/.exec(source);
  if (!block) {
    throw new Error(`${SKILL_FILE.pathname}: expected a leading --- frontmatter block`);
  }

  const fields = {};
  for (const line of block[1].split(/\r?\n/)) {
    const pair = /^([A-Za-z][\w-]*):[ \t]*(.*)$/.exec(line);
    if (pair) {
      fields[pair[1]] = pair[2].trim().replace(/^(['"])([\s\S]*)\1$/, '$2');
    }
  }

  if (!fields.name || !fields.description) {
    throw new Error(`${SKILL_FILE.pathname}: frontmatter needs both "name" and "description"`);
  }

  return { fields, content: source.slice(block[0].length).trim() };
}

/**
 * Register the bundled threat-intelligence skill on `ctx.skills`.
 *
 * `register` files the skill into the calling context's layer. Its returned
 * disposer is already tied to this plugin's fiber, matching the idiom used by the
 * Harness's own bundled skill provider, so it is not wrapped a second time.
 */
function registerSkill(ctx) {
  const { fields, content } = readFrontmatter(readFileSync(SKILL_FILE, 'utf8'));

  ctx.skills.register({
    name: fields.name,
    description: fields.description,
    ...(fields.whenToUse ? { whenToUse: fields.whenToUse } : {}),
    content,
    source: 'bundled',
    provider: name,
    invocation: { modelInvocable: true, userInvocable: true },
    resourceBase: { kind: 'directory', path: fileURLToPath(SKILL_DIRECTORY) },
  });
}

/**
 * Resolve and validate one local file for submission.
 *
 * Path rejection happens before any byte is read: the credential-filename check
 * runs first, and `lstat` refuses a symbolic link at the final component so that
 * following it never happens. Containment is deliberately not re-implemented
 * here — `ctx.fs` is the Harness's own filesystem, so the configured file policy
 * still fences the read, and `lstat` cannot see a link in a parent directory.
 */
async function readCandidate(ctx, rawPath, signal) {
  if (typeof rawPath !== 'string' || rawPath.trim() === '') {
    throw new Error('"path" must be a non-empty string naming a local file');
  }
  if (rawPath.includes('\0')) {
    throw new Error('"path" must not contain a NUL character');
  }
  if (CREDENTIAL_FILENAME.test(basename(rawPath))) {
    throw new Error(
      'refusing to read a credential-like filename; choose a different file, and do not rename or encode it to bypass this check',
    );
  }

  const pathInfo = await ctx.fs.lstat(rawPath, {}, signal);
  if (pathInfo === undefined) {
    throw new Error(`no such file: ${rawPath}`);
  }
  if (pathInfo.type === 'symlink') {
    throw new Error(`refusing to follow a symbolic link: ${rawPath}`);
  }

  const target = await ctx.fs.resolve(rawPath, { signal });
  const info = await ctx.fs.stat(target, signal);
  if (info === undefined) {
    throw new Error(`no such file: ${rawPath}`);
  }
  if (info.type !== 'file') {
    throw new Error(`not a regular file: ${rawPath}`);
  }
  if (info.size !== undefined && info.size > MAX_BYTES) {
    throw new Error(
      `${rawPath} is ${info.size} bytes, above the ${MAX_BYTES}-byte submission limit`,
    );
  }
  if (info.size === 0) {
    throw new Error(`${rawPath} is empty`);
  }

  const bytes = await ctx.fs.readBytes(target, signal, MAX_BYTES);
  if (bytes.byteLength === 0) {
    throw new Error(`${rawPath} is empty`);
  }
  if (info.size !== undefined && bytes.byteLength !== info.size) {
    throw new Error(`${rawPath} changed while it was being read; refusing to submit it`);
  }

  return {
    displayPath: target.displayPath ?? rawPath,
    bytes,
    sha256: createHash('sha256').update(bytes).digest('hex'),
  };
}

/**
 * Register `virustotal_submit_local_file` on `ctx.tools`.
 *
 * The hosted server accepts original bytes rather than a path, and the DSH MCP
 * client cannot expand a local path on its own, so this tool performs the one
 * step no model should: reading the file, proving its SHA-256, and handing the
 * bytes to the connected `submit_file` tool. The nested execution goes back
 * through the registry, so host permissions and guards still decide whether the
 * submission happens.
 */
function registerUploadTool(ctx) {
  ctx.tools.register({
    name: 'virustotal_submit_local_file',
    description:
      'Submit one local file to VirusTotal for analysis by reading its bytes from this machine. ' +
      'Use only when the user explicitly asks to submit that file; ask before sharing their own ' +
      'documents, internal code, credentials or personal data. Computes the file\'s SHA-256 and ' +
      'passes the original bytes to VirusTotal directly, so the content never has to travel ' +
      'through the model as text. Standard submissions are shared with the VirusTotal community ' +
      'and security partners. Files up to 24,000,000 bytes are accepted. If VirusTotal already ' +
      'knows the hash, its existing report is returned without a new upload. Recover an uncertain ' +
      'upload with get_submission(sha256=...) rather than repeating it.',
    parameters: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          description:
            'Path to the local file to submit, absolute or relative to the workspace.',
        },
      },
      required: ['path'],
      additionalProperties: false,
    },
    output: {
      schema: { type: 'object' },
      render: (_args, value) => [
        { type: 'text', text: typeof value === 'string' ? value : JSON.stringify(value, null, 2) },
      ],
    },
    isConcurrencySafe: () => false,
    presentCall(args) {
      const target = typeof args?.path === 'string' ? args.path : '';
      return {
        card: 'generic',
        title: `Submit ${target === '' ? 'local file' : basename(target)} to VirusTotal`,
        kind: 'other',
        rawInput: target,
        ...(target === '' ? {} : { locations: [{ path: target }] }),
      };
    },
    async execute(args, exec) {
      const { displayPath, bytes, sha256 } = await readCandidate(ctx, args?.path, exec.signal);

      const outcome = await ctx.tools.execute({
        callId: `${exec.callId}:virustotal-submit-file`,
        rootCallId: exec.rootCallId,
        parent: exec.token,
        name: SUBMIT_TOOL,
        arguments: { sha256, content_base64: Buffer.from(bytes).toString('base64') },
        ...(exec.agent === undefined ? {} : { agent: exec.agent }),
        signal: exec.signal,
      });

      if (outcome.isError) {
        throw new Error(
          `VirusTotal submission of ${displayPath} failed: ${outcome.error?.message ?? 'unknown error'}`,
        );
      }
      return outcome.value;
    },
  });
}

/** Register everything this bundle contributes. */
function apply(ctx) {
  registerSkill(ctx);
  registerUploadTool(ctx);
}

export { apply, inject, name };
