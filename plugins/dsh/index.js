/**
 * Copyright 2026 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 *
 * VirusTotal for DeepSeek Harness — Host half.
 *
 * The connection itself belongs to `@deepseek-ai/dsh-mcp-client`, inserted by
 * this bundle's patch. This module contributes only the bundled
 * `virustotal-threat-intelligence` skill, so that installing the bundle delivers
 * the tools and their operating guidance together, as the other client plugins
 * in this repository do.
 *
 * The skill body lives in `skills/virustotal-threat-intelligence/SKILL.md` and is
 * the single source of truth for it; this module reads the frontmatter for the
 * name and description rather than duplicating them here.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const SKILL_DIRECTORY = new URL('./skills/virustotal-threat-intelligence/', import.meta.url);
const SKILL_FILE = new URL('SKILL.md', SKILL_DIRECTORY);

/** Cordis plugin name, referenced by this bundle's patch row id. */
const name = 'virustotal-skill';

/** The skill registry this plugin contributes to. */
const inject = ['skills'];

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
function apply(ctx) {
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

export { apply, inject, name };
