/**
 * Copyright 2026 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 *
 * Read-only guard for the `virustotal-lookup` agent preset.
 *
 * The VirusTotal connection and the skill are host rows, so their tools are global
 * and visible to every agent whatever preset it selects. A preset cannot remove
 * them by simply not listing them; it has to deny them.
 *
 * Mounted inside a preset's standing composition, `restrict` applies to that
 * preset's scope, and a restricted-away global reads as absent — so the read-only
 * agent does not merely decline to submit, it has no submission tool at all.
 *
 * Both mechanisms are used deliberately:
 *
 *   - `restrict` hides the names that exist when this plugin activates, which is
 *     what keeps them out of the model's tool list.
 *   - `guard` denies by name at call time, which still holds if the connection
 *     reconnects later and registers a tool this plugin had not seen yet.
 *
 * Report lookups, registered analyses and receipt recovery stay available.
 */
const inject = ['tools'];

/**
 * Every VirusTotal write operation, across both transports.
 *
 * `virustotal_submit_local_file` is this bundle's own tool rather than an MCP one,
 * so it has to be named separately: it delegates to `submit_file` and would
 * otherwise be the one remaining way to publish content from this preset.
 */
const DENIED = [
  'mcp__virustotal__submit_file',
  'mcp__virustotal__submit_attachment',
  'mcp__virustotal__submit_url',
  'mcp__virustotal__reanalyze_domain',
  'mcp__virustotal__reanalyze_ip',
  'virustotal_submit_local_file',
];

/** Cordis plugin name. */
const name = 'virustotal-read-only';

/** Reason returned to the model when it attempts a denied call. */
const REASON =
  'This agent preset is read-only for VirusTotal: reports, analyses and receipt recovery only. Select the VirusTotal Triage preset to submit or reanalyze.';

/** Remove every VirusTotal write tool from this preset's scope. */
function apply(ctx) {
  // `restrict` rejects unknown names, and the submission tools legitimately do not
  // exist when the connection has no working credential, so deny only what is
  // actually registered. The guard below covers anything that appears later.
  const present = DENIED.filter((toolName) => ctx.tools.get(toolName) !== undefined);
  if (present.length > 0) ctx.tools.restrict({ deny: present });

  ctx.tools.guard((execution) => (DENIED.includes(execution.name) ? REASON : undefined));
}

export { apply, inject, name, DENIED };
