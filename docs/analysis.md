# Submit files and network indicators, then recover the selected analysis

Version 0.9 adds explicit URL submission and domain/IP reanalysis to file submission and selected-analysis recovery. Network tools require a compatible VTAI service; the file CLI remains compatible.
A compatible VTAI submission and analysis service is required; see
[service validation](clients.md#service-and-workflow-validation) for observed
workflows and their limits. Bare `vt-mcp` still starts the MCP server over stdio.

## Autonomous MCP workflow

With the compatible VTAI network-analysis service, HTTP and stdio expose ten common tools:
four report lookups, `get_analysis`, `submit_file`, the three network submission tools
and `get_submission`. Local stdio adds `submit_local_file`, for eleven tools in total. Existing report lookups
do not upload or request a rescan.

| Tool | Contract |
|---|---|
| `submit_file(sha256, content_base64)` | Submit base64-encoded bytes whose decoded SHA-256 matches `sha256`; maximum **24,000,000 decoded bytes**. Available over HTTP and stdio. |
| `submit_local_file(path, expected_sha256=None)` | Copy a regular file accessible to the **local vt-mcp process**, calculate its SHA-256 and submit that copy; maximum **32,000,000 bytes**. If supplied, the expected digest must match. Local stdio only. |
| `submit_url(url, request_id)` | Request standard analysis of one HTTP(S) URL. |
| `reanalyze_domain(domain, request_id)` | Request domain reanalysis; no scheme, path or port. |
| `reanalyze_ip(ip, request_id)` | Request reanalysis of one IPv4 or IPv6 address. |
| `get_submission(sha256=None, request_id=None)` | Read an owned receipt using exactly one file SHA-256 or network request ID. |
| `get_analysis(analysis_id, request_id=None)` | Read selected registered analysis evidence. Pass the network receipt's request ID when applicable. |

The submission tools operate in **standard mode**. VT-MCP adds no `consent` Boolean,
confirmation argument or per-call human prompt. The client owner configures host
authorization separately: its policy can permit the assigned operation without
another prompt, ask, or deny it. Existing host grants and VTAI rights still apply.
Submit files or request URL, domain or IP analyses only when the user explicitly
requests that action. A missing report or unfamiliar file is not permission to submit.
Ask before submitting the user's own documents, internal code, credentials or
personal data, including when present in an attachment or unfamiliar file. See the
[client permissions](clients.md), including
[Codex's per-tool approval](clients.md#codex-approval-for-submission-tools).
The MCP tool does not bypass host controls or confer broader VTAI rights. Do not
grant access to files that the agent is not authorized to disclose.

Standard submission is not confidential: content is sent through VTAI to VirusTotal
and may be available to its community and security partners. Inline base64 content
also travels in MCP tool arguments, which your host or model provider may retain.
The local-file tool keeps file bytes out of those arguments; the authorized copy
still goes to VTAI and VirusTotal. It does not make the upload private.

For a local stdio agent, a task can be:

> Submit `/absolute/path/authorized-public-file.txt` using `submit_local_file`.
> Pass the expected SHA-256 if it was supplied with this task. Call `get_submission`
> for that same hash and account, then read its registered ID with `get_analysis`.
> If sending is uncertain, recover the receipt without submitting again. Report the actual status,
> source, analysis date and engine coverage; completion is not a safety verdict.

A remote host instead provides `sha256` and `content_base64` to `submit_file`.
It must possess the actual bytes and follow the sharing guidance above; the server
cannot read a client-side path. Neither tool fetches an arbitrary URL, walks
directories, extracts an archive,
executes the file or adds a comment. Empty files are permitted. The 24 MB inline
ceiling accounts for base64 expansion inside the bounded HTTP request; it is not
32 MB of decoded content. The local/binary path retains the 32,000,000-byte limit.

The MCP and API file submission paths use the same VTAI identity, rights and
per-account receipts. For a new submission attempt, VTAI verifies the original
bytes and checks their hash before uploading: only a confirmed missing report
allows an upload. This internal check does not charge a query when the file is
unknown. A separate client-side hash lookup is not required.

If the file is already known, VTAI does not upload it. Returning its report in
`exists` consumes one query; if quota is exhausted, the request fails without
returning the report or uploading the file. `exists` describes the existing report,
not a new analysis. Authentication, sharing permission, file limits, service
capacity and submission recovery still apply.

Keep the returned SHA-256 and any analysis ID. If sending was ambiguous, use
`get_submission(sha256)`; **do not call either submission tool again to resolve
uncertainty**. There is no automatic POST retry. A `submission_unknown` outcome may
remain unknown permanently. A missing receipt is not evidence that an earlier
ambiguous upload never happened, and a later file report cannot replace the
selected analysis. Cancellation does not withdraw bytes already accepted.

Use the response to choose the next read:

| Submission or receipt outcome | Next step |
|---|---|
| `submitted` with an analysis ID | Read `get_submission` for the same SHA-256/account when recovering the receipt; use its registered ID with `get_analysis`. |
| `submission_unknown`, lost response or cancellation | Read only `get_submission` for recovery. If no registered ID is available, stop the analysis cycle without another submission. |
| `exists` | Report the existing file report as such. Do not invent a new analysis ID or completion. |

`submitted` means VTAI durably registered an analysis ID, not completion. Read that
ID with `get_analysis`; each call performs one bounded read and consumes the
shared query allowance. Repeated report lookups also count again, including cache
hits and hashes with no report. The agent can make later reads according to the
returned
status and retry delay, within a finite task budget. No MCP call waits indefinitely
or invents completion, and no credential is a tool argument.

### Query quota for file workflows

| Operation | Query cost |
|---|---:|
| Contribute valid file bytes after the server confirms the hash is unknown | 0 |
| Submit a known file and receive its existing report; no upload occurs | 1 |
| Explicit report lookup, including a missing report, cache hit or repeat | 1 |
| Recover an owned receipt with `get_submission` | 0 |
| Read a registered analysis with `get_analysis`, including a repeat | 1 |

An explicit hash lookup that returns no report still consumes its query. A later
contribution of that unknown file adds no query charge. Exhausted query quota
does not prevent contributing a file confirmed unknown, but it prevents obtaining
an existing report or reading analysis results until quota is available. Receipt
recovery does not start another upload. Network-analysis dispatch retains its
[separate query accounting](#network-analysis-and-recovery).

### File contribution limits

Unknown files have an independent allowance of **20 files per fixed 60-second
window and 500 per UTC day**. Agent Tokens use their registered identity; OAuth
connections share the signed-in account's allowance across grants. The same limit
covers MCP, local/binary and legacy multipart file submission paths. Existing size
and permission checks still apply.

VTAI validates bytes and confirms the hash is unknown before reserving this
allowance. Known reports, owned receipt recovery and failed validation or hash
prechecks do not use it. An admitted attempt remains counted if later processing
fails or becomes uncertain. Concurrent attempts for the same hash can consume more
than one admission even though the durable receipt prevents another dispatch.
The allowance limits files, not bytes, and uses a separate counter from query quota.

A `contribution_limited` error (HTTP 429) includes a retry delay; the file has not
been dispatched and no new receipt has been reserved. A
`contribution_unavailable` error (HTTP 503) means admission could not be confirmed;
no upload starts. Honor `Retry-After` or `retry_after_seconds` and avoid tight
loops. A remote HTTP caller can deliberately try again after the delay for these
specific errors. Do not apply that rule to an uncertain submission.

The local stdio tools and CLI retain their durable reference even after a rejected
attempt. A later call for that hash only recovers the receipt and can return
`not_found`; it does not resend automatically. Keep that state and do not change
identity to force a retry. New identities or accounts must not be created to evade
either contribution or query limits.

### MCP recovery state

Both file submission tools in the local stdio server reuse the CLI's
[durable reference](#cli-durable-recovery-before-sending), before sending a POST.
The state belongs to the vt-mcp process and is shared by clients using the same
service, credential and state directory. Configure `XDG_STATE_HOME` on that process
to choose its state root; neither MCP tool has a `state-dir` argument. Preserve the
directory after interruption. An existing reference permits only receipt recovery,
including when the original dispatch or local acknowledgement is uncertain.

Remote HTTP uses VTAI's per-account receipt; it does not create this local reference
on the assistant's machine. Keep the SHA-256 and use `get_submission` with the same
account. Do not change accounts or delete local state to work around an unknown
outcome. A repeated successful receipt read is recovery, not evidence of another
upload or scan.

### When the client cannot transmit file bytes

For a submission explicitly requested by the user, use the available submission
tool when the client can supply the actual bytes.
If it cannot, first calculate the file's SHA-256 locally, or ask the user for it,
and call `get_file_report(hash)`. Use an existing report without uploading the
file. Only an explicitly requested submission and a confirmed missing report permit
offering the existing
[VirusTotal upload page](https://www.virustotal.com/gui/home/upload), under the
same public-sharing and sensitive-content guidance above. Permission, quota or
service errors do not establish absence and do not permit an upload.
Remote HTTP alone does not establish whether a host can access an attachment or
transmit its bytes; capabilities depend on the actual client and workflow.

After the user uploads the confirmed unknown file through the website, read
`get_file_report(hash)` using the same hash. A web upload creates no VTAI receipt or registered analysis
ID: `get_submission` and `get_analysis` cannot recover that external upload.
The report may not be available immediately; a missing report stays unknown.
Limit later reads to the task's time and request budget. Every lookup
counts toward quota, including missing reports and cache hits. Do not upload again
just because a report is not yet available.

The [client guide](clients.md) lists exact grants in Agy → Claude Code → Codex order.
The [0.8 submission evidence](clients.md#version-08-submission-evidence) records
five native-client cycles in staging and five against a production candidate,
preserving pending and completed results. Later API reads confirmed both candidate
analyses completed. The public rollout and separate direct SDK checks are now
accepted; the native sessions retain their candidate-route scope, and the
historical 0.7 read-only sessions retain theirs.

## Network analysis and recovery

Use `submit_url`, `reanalyze_domain` or `reanalyze_ip` only when the user explicitly
requests that analysis.
A missing report remains unknown. Domain evidence does not establish a URL's safety.
The tools ask VirusTotal to perform the operation; the local package never visits a
target or calls the VirusTotal API directly. Follow the sharing guidance above.
Standard sharing includes the complete URL and its query/fragment;
ask before submitting a URL containing credentials, personal data or other user-owned
sensitive content.

Before calling, generate a canonical lowercase UUIDv4 and **save it in the caller's
existing durable task state**. For example, Python's `str(uuid.uuid4())` produces the
required format. Retain the ID and its intended operation before sending, so a
process restart can recover it. There is no confirmation parameter, automatic ID
creation or additional local network-receipt store in this package.

1. Call the chosen tool with its indicator and the retained `request_id`.
2. On interruption, read `get_submission(request_id=...)` using the same ID and identity.
3. When submitted, call `get_analysis(analysis_id=..., request_id=...)` with both values
   from the receipt. Respect the returned polling delay and a finite task budget.

Reusing an ID identifies the same operation, not a fresh rescan. A changed kind or
normalized target conflicts without another dispatch. Do not replace the ID to retry
an uncertain operation. A deliberate later analysis, or a corrected operation after
a confirmed rejection, uses a new ID. The package never automatically retries POST.

| Receipt status | Meaning and action |
|---|---|
| `submitted` | VTAI registered an analysis ID; read that selected analysis. This is not completion. |
| `submission_unknown` | Acceptance or registration could not be confirmed. Recover the same receipt; uncertainty may be permanent. |
| `rejected` | Confirmed rejection is terminal for this ID. Follow its closed error: correct input, resolve permission, or wait for quota before intentionally using a new ID. |

Network receipts contain `status`, `mode`, `request_id`, `indicator_type`,
`analysis_id`, `analysis_status`, `next_poll_after_seconds` and `can_resubmit:false`.
Only rejected receipts add `error`, with a closed code/message, `retryable:false`
and an optional retry delay. They contain neither raw targets nor file fields.
MCP writes return `isError` for rejected/unknown outcomes and retain the receipt;
reading such a receipt is a successful read of its actual state.

Network analysis results preserve `request_id`, `indicator_type` and `report_id`
instead of a file SHA-256. A pending result may have no report ID or link. Completed
results require matching selected-analysis evidence and its typed VirusTotal report
link, as checked by VTAI. Upstream analysis IDs can recur: an omitted `request_id`
works only when the receipt is unambiguous; otherwise supply the receipt's ID after
`receipt_conflict`. Never substitute the newest report for the selected analysis.

With direct REST, POST JSON exactly `{"indicator_type":"url","indicator":"https://example.com/"}`
to `/api/v3/network-submissions/{request_id}`, or use `domain`/`ip` with the matching
indicator. Authenticate with your existing Agent Token and send
`Content-Type: application/json` and `X-VTAI-Consent: standard-v1`. The stdio client
sets those submission headers itself. Targets appear only in the JSON input, never
in the receipt URL. Recover with GET on the same path and read
`/api/v3/analyses/{analysis_id}?request_id={request_id}`. URL-encode the opaque analysis
ID as one path segment. REST returns 202 for an uncertain submission, and a confirmed
rejection returns its 422/403/429 error with `detail.submission` recovery metadata.

OAuth network writes require both `vt:reports:read` and `vt:network-analysis:write`.
The existing file-write permission does not grant network writes, and old grants do
not expand automatically. Static Agent Tokens retain their VTAI rights and quotas.
Receipt recovery makes no upstream call and consumes no query quota. A newly admitted
network dispatch and each selected-analysis read use the ordinary query allowance.

The following local-state and CLI submission sections apply to files. Network writes
are MCP tools or direct REST operations; no new CLI subcommand is required.

<a id="authorize-one-copy"></a>

## CLI: authorize one copy

Configure your existing VTAI credential using the [access guide](access.md). The
CLI uses `VTAI_TOKEN_FILE` or `VTAI_TOKEN` and `VTAI_BASE_URL`; authentication is
`x-apikey`. Do not put the credential in command arguments, prompts or receipts.

```bash
vt-mcp submit /absolute/path/authorized-file.txt --mode standard
```

The CLI opens one readable regular file, copies it into a private temporary file
and calculates its SHA-256 and size before asking for confirmation. It accepts
empty files and at most **32,000,000 bytes**. Directories, devices, FIFOs and final
symlinks are rejected on the tested POSIX platform. It does not download a URL,
walk directories, extract archives, accept archive passwords or add comments.
Detected source modification during copying stops the operation. A later change
to the original path does not change the copy authorized and sent.

The interactive prompt displays the configured service, `standard` mode, SHA-256
and byte count. Type **`SUBMIT`** to authorize that copy. Refusal, EOF or an
interrupt before confirmation sends no sample bytes and starts no POST. The local
source pathname is not sent in HTTP headers/body metadata or included in receipts.
The copied file's bytes are, of course, disclosed by an authorized submission.

Standard submission is **not confidential**. VirusTotal shares reports with its
community; submitted content may be accessible to security partners and premium
customers. Use this flow only for content you are authorized to disclose under
those conditions. Cancelling the CLI does not withdraw an accepted file.
[VirusTotal: how sharing works](https://docs.virustotal.com/docs/how-it-works).
Private Scanning is a different service with different coverage; `--mode standard`
does not enable it. [VirusTotal Private Scanning](https://docs.virustotal.com/docs/private-scanning).
These sources were checked on 2026-09-06.

Noninteractive **CLI** use still requires both explicit acceptance and the expected SHA-256; these are not MCP tool arguments:

```bash
vt-mcp submit /absolute/path/authorized-file.txt --mode standard \
  --accept-standard --expected-sha256 EXPECTED_LOWERCASE_SHA256
```

Replace the digest with the one approved by your policy outside model context.
The CLI compares it with the private copy. Either flag alone, an invalid digest or
a mismatch prevents submission. This interface does not authorize arbitrary CI
artifacts or confidential repository contents. The caller must establish authority
for the exact bytes before invoking it.

VTAI checks for an existing file report first. Only confirmed absence permits the
new submission path to proceed. `status: exists` returns that existing report and
does not claim a new analysis. The CLI does not make a second precheck that would
consume another query allowance.

<a id="durable-recovery-before-sending"></a>

## CLI durable recovery before sending

Before dispatch, the CLI exclusively creates and synchronizes a small local reference.
POSIX uses file and directory fsync; Windows uses local NTFS, write-through creation
and FlushFileBuffers. If private durable storage cannot be
confirmed, **no POST starts**. Printing the digest alone is not this guarantee.
The JSON stores only:

```json
{
  "schema_version": 1,
  "service": "https://ai.virustotal.com/api/v3",
  "mode": "standard",
  "sha256": "THE_COPIED_FILE_SHA256"
}
```

The default root is `$XDG_STATE_HOME/vt-mcp`, or `~/.local/state/vt-mcp` when the
XDG value is absent or relative. `submit --state-dir /absolute/private/state`
selects a different root, useful for an isolated account or test runner. The root
and its internal directories must be private to the current user; new directories
use mode 700 and reference files mode 600 on POSIX. Windows uses a protected ACL
granting access only to the current user. Windows receipt storage must be local NTFS;
network shares, alternate streams and reparse points are rejected. Parent handles
remain open while creating the receipt. Unsupported storage fails before POST.
This is an OS storage guarantee, not a claim that tests simulate physical power loss.

Internal directories are keyed by service and an irreversible, service-specific
fingerprint of the credential. The fingerprint is local indexing metadata only:
it is not in the reference JSON, HTTP requests, stdout or diagnostic messages.
The raw credential is never stored there. Different credentials use different
namespaces; the CLI does not infer that two credentials identify the same account.
The reference filename is the SHA-256, and the content does not include the sample,
original pathname or analysis result.

A reference already present for that service/credential/SHA allows **only a receipt
GET**, never another POST. This also applies after response loss, an uncertain
local write acknowledgement, or a crash between saving the reference and actually
sending. A missing server receipt does not make the local operation eligible for
automatic resubmission. A concurrent process may receive a closed storage error
while another finishes creating the reference; it must not bypass that state.

Keep references after interruption and preserve them when moving the client. Do
not delete one to turn recovery into another submission. Rotating a credential
changes the local namespace and leaves the old reference intact. Use
`vt-mcp submission SHA256` with the current authorized credential to recover on
VTAI; access still depends on the account, and a new credential is not proof of
the same identity. A different or deleted local state directory does not carry
the earlier client's no-repeat guarantee. VTAI independently retains its own
per-account receipt; it makes no cross-account deduplication claim.

## Submission outcomes and recovery

MCP submission and receipt tools use the same `submitted`, `exists` and
`submission_unknown` response states below. MCP errors set `isError` and retain
closed recovery metadata; raw provider errors and credentials are not exposed.

Normal CLI stdout is one final JSON object. Prompts go to stderr. A submitted result
has this shape; `analysis_status: null` means the accepted descriptor did not
establish an analysis state:

```json
{
  "status": "submitted",
  "mode": "standard",
  "submission_id": "SHA256",
  "sha256": "SHA256",
  "size": 313,
  "analysis_id": "OPAQUE_REGISTERED_ID",
  "analysis_status": null,
  "next_poll_after_seconds": 5,
  "can_resubmit": false,
  "report": null
}
```

`submitted` means an analysis ID was durably registered; it is **not completion**.
`submission_unknown` has null analysis ID, state, next poll and report. It means
processing or acceptance could not be confirmed and can remain unknown permanently.
It is neither definitive rejection nor permission to upload again. `exists` has
an existing `report: {"data": ...}` and no new analysis ID.

Recover by the copied SHA-256, even when the original CLI never received an ID:

```bash
vt-mcp submission LOWERCASE_SHA256
```

This reads only the current account's receipt; it does not upload, contact
VirusTotal or spend analysis-query quota. A 404 means no receipt was available to
that account at the time of the read. It does not resolve an earlier ambiguous
local dispatch. If the result remains unknown, the selected analysis may never
be recoverable. A later file report found by hash must not be attributed to that
uncertain analysis.

The CLI never automatically retries a POST. Its single POST sends raw bytes
with `Content-Type: application/octet-stream` and
`X-VTAI-Consent: standard-v1` to `/api/v3/submissions/{sha256}`. There is no filename,
multipart metadata, caller-selected idempotency key or redirect following.
Timeouts, lost responses and invalid success responses preserve uncertainty and
the durable reference. Known access/quota/input errors remain distinct; their
`retryable` metadata applies only to reads, not to repeating this submission.

## Read the selected analysis

```bash
vt-mcp analysis -- OPAQUE_REGISTERED_ID
vt-mcp analysis --wait 180 -- OPAQUE_REGISTERED_ID
```

An analysis ID is opaque, is not a URL destination, and does not grant access.
It is bounded to 1024 UTF-8 bytes without whitespace/control characters; `.` and
`..` are invalid. Quote shell-sensitive IDs as individual arguments and use `--` before the ID
so a leading dash is not parsed as an option. The client
encodes the entire ID as one HTTP path segment. VTAI verifies ownership and current
access for every read.

`status` is `pending` or `completed`. `analysis_status` preserves `queued`,
`in-progress`, `completed` or null. Pending results can retain partial evidence.
`not_available_yet` means no analysis evidence was available; `result_not_ready`
means the provider reported completion but its matching typed result was not yet
available. Completion requires the registered analysis to be completed with valid
stats/results and a matching file or network result, as verified by VTAI.

The returned stats, engine results and analysis date belong to **that analysis**.
No latest report request replaces them. `retrieved_at` is the query time;
missing analysis date remains null. Failed or timed-out engines are evidence,
not a fabricated global `failed` state. Labels and analysis content are untrusted
data. [VirusTotal analysis object](https://docs.virustotal.com/reference/analyses-object).

Each valid owned analysis lookup consumes VTAI query quota. `--wait` accepts a
finite number of seconds from 0 to 300; zero performs just one read. Positive
waiting starts with a read, uses intervals of at least 5 seconds increasing up to
30 seconds, honors a longer sanitized Retry-After, and retries only safe reads.
No retry runs after the finite wait budget or after cancellation.

With positive `--wait`, the latest observed analysis gains:

```json
"wait": {"status": "budget_exhausted", "last_error": null}
```

`wait.status` is `completed` or `budget_exhausted`; a transient error after the last
pending observation appears as a closed `last_error`. Ending the budget keeps the
observed analysis pending. When there was no valid result, the CLI returns an
error instead of inventing pending evidence. A non-retryable read error, such as
denied access, ends waiting with that error. Waiting is optional CLI behavior;
the MCP tool performs one bounded read and never polls.

## Limits and diagnostics

MCP inline submissions accept at most 24,000,000 decoded bytes; local-file MCP
and the binary CLI path accept at most 32,000,000. Transport limits can reject a
request before tool dispatch. Inputs and responses remain bounded, and file bytes
are never returned as a tool result.

Local stdio applies a **150-second operation budget** to either submission tool,
covering preparation, durable state and dispatch or receipt recovery. Configure the
MCP host's tool deadline with room for that operation and cleanup; the
[Codex examples](clients.md#codex-cli--local-stdio) use 180 seconds. A shorter host
deadline can interrupt the caller without proving that the service did not accept
the file. Recover by receipt instead of retrying submission.

The underlying client POST budget is 130 seconds, including for the compatible
CLI, separate from existing report-tool timeouts.
Each analysis or receipt GET is bounded to 35 seconds; a positive `--wait` further
bounds the whole polling loop. Responses are capped at 256 KiB, schema-validated
and minimized; raw provider bodies and exception messages are not reflected.
Copy preparation checks a fifteen-second budget between local operations, including
its final preparation step. Filesystem operations blocked inside the kernel are
not guaranteed interruptible. Temporary copies close and are removed on completion,
failure or interruption.

| Exit | Meaning |
|---|---|
| 0 | A valid `submitted`, `exists`, `pending` or `completed` response; inspect `status` |
| 3 | `submission_unknown`, including an error with unknown recovery metadata |
| 2 | Closed configuration, consent, storage, input, access or service error |
| 130 | Handled local interrupt; output can remain `submission_unknown` after dispatch |

An error has `status: error` and an `error` object with a closed code and message.
API errors also carry HTTP status, read retryability and optional retry delay.
When a local submission reference exists, `submission` retains safe recovery
metadata. A terminating signal can stop the process without JSON; the reference
still enables a later receipt read. Exit 0 is not a security approval, and exit 3
does not imply nothing was sent.

Do not paste credentials or private file contents into model context to diagnose
these outcomes. `local_state_unavailable` means storage was not confirmed before
POST; `access_denied`, `rate_limited`, `not_found`, `timeout` and
`submission_unknown` have different meanings. Stopping or removing the CLI does
not revoke access or withdraw an uploaded sample. Revoke credentials separately
through the [access workflow](access.md).

## Validation scope

The autonomous 0.8 MCP workflow has its own
[staging and candidate evidence record](clients.md#version-08-submission-evidence), separating
tool invocation, new dispatch, receipt recovery and selected-analysis completion.
The following evidence remains scoped to earlier releases.

[Service validation](clients.md#service-and-workflow-validation) records real
staging recovery and a separate Codex public HTTP read of an already-submitted
analysis. The Codex session made one `get_analysis` call and preserved its
selected identity and completed evidence, including unsupported and failed
engine results. It did not submit a file or validate analysis through stdio.
These observations are distinct from local tests using harmless generated text
and mocked or loopback VTAI. A recovered result does not imply a new upload
occurred, and `completed` is not a safety verdict.

The legacy upload route has different guarantees and is not used or upgraded by
this client. These instructions do not authorize submitting private sources,
build artifacts, logs or dependencies.
