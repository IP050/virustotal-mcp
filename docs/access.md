# Configure free VTAI access

For Windows, use the [automatic setup guide](https://ai.virustotal.com/connect/mcp) and select Windows PowerShell. The installer creates a user-only Windows ACL. The shell examples below are for Linux/macOS; `chmod` is not a Windows access-control mechanism.

A VTAI credential identifies one registered agent and carries VTAI's current rights and quotas. It is not a VirusTotal API key or a model-provider key. Free access does not imply anonymous or unlimited use, or free inference from your chosen assistant.

Keep registration, credential entry, diagnosis and revocation outside model conversations. Use a terminal you control or the VTAI connection page. Do not ask an assistant to read your token file, environment or client credential settings.

## Register once or reuse existing access

Reuse an existing VTAI credential if you have one. Registration is an explicit setup action; it is not a tool and does not run when vt-mcp starts.

Use the [Agent Token setup](https://ai.virustotal.com/connect/mcp?client=other&transport=http&auth=token#access-heading) for browser registration or reuse. Reconnecting or changing transport does not register another agent. This page lets you register explicitly, request a token-file download, check access and revoke a credential. A download request does not prove the file was saved; confirm protected storage yourself. Checking access calls `GET /api/v3/agents/me/access` and consumes no query quota. It checks authentication, not a report or your model's use of MCP; an actual report query is a separate, charged check. Registration may have succeeded if the connection fails; do not register again automatically.

The [browser acceptance table](clients.md#distribution-and-browser-acceptance) records the real flow through a route pinned to the production candidate, separately from ordinary public navigation and package release acceptance. If the page is unavailable, check the exact endpoint/prefix and [service validation](clients.md#service-and-workflow-validation). For a terminal setup, the explicit API example below is an alternative; opening the API URL alone does not register an agent.

For local setup, this terminal script calls the existing registration API and writes the credential without printing it. It refuses an existing path and uses owner-only permissions on POSIX. Run it only once; if the request times out after registration, registration may have succeeded. Diagnose that uncertainty before creating another agent.

```bash
python3 - <<'PY'
import json
import os
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

path = Path.home() / ".config" / "vt-mcp" / "token"
path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
path.parent.chmod(0o700)
if path.exists() or path.is_symlink():
    raise SystemExit("An existing credential path is already configured.")
request = Request(
    "https://ai.virustotal.com/api/v3/agents/register",
    data=json.dumps({"agent_family": "vt-mcp", "agent_version": "0.9.9"}).encode(),
    headers={"Content-Type": "application/json"},
    method="POST",
)
try:
    with build_opener(NoRedirect).open(request, timeout=20) as response:
        raw = response.read(65537)
        if len(raw) > 65536:
            raise ValueError("response limit")
        token = json.loads(raw)["agent_token"]
    if not isinstance(token, str) or not token.startswith("vtai_"):
        raise ValueError("credential format")
    if not 6 <= len(token) <= 256 or any(not 33 <= ord(c) <= 126 for c in token):
        raise ValueError("credential format")
except (HTTPError, URLError, TimeoutError, ValueError, KeyError, TypeError):
    raise SystemExit("Registration was not confirmed. No credential was saved.") from None
try:
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as output:
        output.write(token)
except OSError:
    raise SystemExit("Registration returned access, but saving failed. Resolve local storage before retrying.") from None
print("VTAI credential saved. Registration is not needed at each startup.")
PY
```

An existing credential can instead be saved using a trusted editor or password manager to `~/.config/vt-mcp/token`, as a single value. Do not put it in a shell command or a project file. On POSIX, protect the directory with mode `0700` and the file with mode `0600`. If you downloaded a token, a browser does not guarantee those permissions: move it to protected storage and remove the extra download after verifying storage. Windows needs equivalent user-only file access; the POSIX instructions are not Windows validation.

## Local stdio

Install the wheel using the [README](../README.md), then add your client using [client setup](clients.md). Configure only the file path:

```text
VTAI_TOKEN_FILE=~/.config/vt-mcp/token
```

vt-mcp reads the file at startup and uses `x-apikey` for its VTAI requests. Restart its client process after replacing the file. `VTAI_TOKEN` is an alternative for direct process configuration; setting both credential options is an error.

## Remote client environment

Remote MCP uses `https://ai.virustotal.com/mcp`, not the REST URL ending `/api/v3`. Existing clients can keep using **`x-apikey`**. VTAI 0.8.1 additionally accepts the same VTAI credential in **`Authorization: Bearer`** on protected REST routes and MCP. This backend option does not require a vt-mcp 0.8.0 package upgrade.

Use the host's supported environment-header reference from the [configuration fragments](../examples/client-configs/README.md). `VTAI_MCP_TOKEN` is an arbitrary host-side variable name, chosen to avoid conflict with a stdio server's `VTAI_TOKEN_FILE`.

For the verified Antigravity CLI (`agy`) token setup, use [stdio with a token file](clients.md#antigravity-cli-agy); version 1.1.27 sent tested HTTP header variables literally. A separate [native Antigravity OAuth recipe](google-clients.md#antigravity-native-oauth) avoids static header expansion and retains its own validation limits. Claude Code and Codex support the remote configurations described here.

### Choose one authentication header

Configure **one** credential method per connection: `x-apikey` or `Authorization: Bearer`. Both identify the same VTAI agent and share its rights, quotas and revocation. Sending both is rejected, even if their values match; an invalid Bearer does not fall back to `x-apikey`. Tokens in URLs, query parameters or request bodies do not authenticate a request.

For the Bearer alternative, use the host's protected environment reference: [Claude Code](clients.md#claude-code) expands `Bearer ${VTAI_MCP_TOKEN}` in its Authorization header, and [Codex](clients.md#codex-cli--remote-http) supports `bearer_token_env_var = "VTAI_MCP_TOKEN"`. Remove any `x-apikey` mapping from that server entry when selecting Bearer. The examples contain a variable name, never a credential value. See the [scoped native Bearer checks and deployment status](clients.md#bearer-authentication-validation); earlier HTTP workflow evidence used `x-apikey`.

The credential described here is a static VTAI Agent Token. Reuse or explicitly
register it as described above; it is not a VirusTotal API key, Google access
token or model-provider login.

For browser sign-in, VTAI also provides MCP OAuth with discovery, scoped consent,
refresh and revocation. Configure `https://ai.virustotal.com/mcp` without a static
header and use the client's OAuth login flow. This grants a separate OAuth
connection; it does not create a static Agent Token. OAuth access applies to MCP,
while local stdio and direct REST access continue to use an Agent Token. See the
[current connection guide](https://ai.virustotal.com/connect/mcp) and the
[hosted setup and validation guide](hosted-clients.md). For ChatGPT Work, follow
the [account connection steps](hosted-clients.md#connect-chatgpt-work) after
creating the application; no static Agent Token is needed for that OAuth flow.
Initial consent, an IP report, automatic token renewal and a subsequent report
after token expiry were verified in ChatGPT Work on 2026-09-24. Revocation from
the hosted application, incremental permissions and write workflows remain
separate checks; see the [validation scope](hosted-clients.md#validation-scope).

OAuth URL submission and domain/IP reanalysis require `vt:reports:read` plus
`vt:network-analysis:write`. Existing file-write grants do not include that scope
and are not expanded automatically. Reauthorize the connection when network writes
are needed. Static Agent Tokens continue to use their current VTAI rights and quotas.
See [network analysis and recovery](analysis.md#network-analysis-and-recovery).

The Bearer scheme is case insensitive and the token is case sensitive. The configured header must use spaces between the scheme and token, without quotes, surrounding whitespace, tabs or comma-separated credentials. The examples below load the token for either supported header mapping.

In a human-controlled Bash terminal, load the file without printing its value, then launch the client:

```bash
(
  set +x
  unset VTAI_MCP_TOKEN
  IFS= read -r VTAI_MCP_TOKEN < "$HOME/.config/vt-mcp/token" || test -n "$VTAI_MCP_TOKEN" || exit 1
  test -n "$VTAI_MCP_TOKEN" || exit 1
  export VTAI_MCP_TOKEN
  exec claude
)
```

Use `exec codex` instead for Codex, with its matching header configuration. A nonempty first line works with or without a trailing newline; a missing file or empty first line prevents launch. The subshell does not leave a new export in the parent shell. The variable lasts for that client process, and a previously opened GUI will not inherit it. Do not use a header flag containing an expanded credential: it can put the secret in process arguments and saved configuration. File and environment storage avoid normal disclosure in prompts; they do not isolate credentials from software with permission to read them.

## Diagnose the right layer

1. Check the installed client version and `vt-mcp --version` for stdio. Confirm the executable PATH and file access without displaying the credential.
2. Inspect the client's MCP status. A configuration parser or `tools/list` result proves only that layer. In stdio, discovery does not authenticate a VTAI request.
3. Make one explicit report query through the client. Use the empty-file SHA-256 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`, or `example.com`. This consumes an admitted query without uploading a file or sending an explicit analysis POST from VTAI; VirusTotal controls upstream processing. Check source, analysis date, coverage and report link.
4. Confirm that the assistant actually called a tool and used its result. A generic SDK test or successful connection does not establish a model workflow in another client.

| Observation | Meaning / action |
|---|---|
| 400 / Bearer `invalid_request` | Malformed or repeated Bearer authentication, or both credential methods sent together. Keep exactly one valid header mapping. |
| 401 | No supported credential, or an invalid, unknown, expired or revoked Bearer token. Check the mapping and environment source without displaying the value. |
| 403 / `access_denied` | Legacy `x-apikey` was rejected, or the operation was denied after authentication. Check the structured error and current access. |
| 429 / `rate_limited` | Wait for a supplied retry delay; repeated retries consume resources. |
| 429 / `contribution_limited` | The independent file allowance is exhausted; honor the delay and follow [contribution recovery](analysis.md#file-contribution-limits). |
| 503 / `contribution_unavailable` | File admission could not be confirmed, so no upload starts; retain state and honor the retry delay. |
| Tool result `not_found` | No report was found; this is not a safety verdict. |
| HTTP 404 for `/mcp` or `/connect/mcp` | Check endpoint, prefix and deployment flags; this is not an unknown indicator result. |
| Timeout / service error | A failed lookup is not a clean report. Check service status; do not silently submit a sample. |

REST and MCP share VTAI admission and quotas. Report and analysis reads consume query quota on every call; missing reports, cache hits and repeats still count. Contributing a file confirmed unknown by the server and recovering an owned receipt consume no query quota. A known file is not uploaded: returning its existing report requires one query and fails without a report when quota is exhausted. See [file workflow quota](analysis.md#query-quota-for-file-workflows).

Unknown-file contributions are limited separately to **20 files per fixed minute and 500 per UTC day**, per Agent Token identity or signed-in OAuth account, shared across upload paths. Admitted attempts count even if later processing is uncertain. Do not create additional identities or accounts to evade these or query limits. See [contribution limits](analysis.md#file-contribution-limits).

Upstream failures still consume an admitted query. The stdio wrapper defaults to a 15-second total request deadline; the backend lookup has its own 35-second limit. A client timeout can happen first, and an already admitted request may complete later. Show only sanitized errors to the model; never paste raw auth headers or debug logs into chat.

Authentication failures use `Cache-Control: no-store`. Bearer challenges retain `realm="VTAI"`; rejected Bearer tokens add `error="invalid_token"`, and malformed Bearer requests add `error="invalid_request"`. With OAuth enabled, MCP challenges include a `resource_metadata` link for discovery. A missing-credential MCP response also links to setup and the static-token registration recipe for headless clients. Legacy `x-apikey` rejections retain 403 without a Bearer challenge. Access-storage unavailability remains 503. Permission, quota and tool errors after authentication are separate from credential rejection.

## Disconnect and reconnect

Before removing a connection, recover any uncertain submission through that same connection and preserve its receipt identifiers. Do not replay a submission to resolve uncertainty. Then remove or disable the `virustotal` entry in the client and restart/reload it. [Client setup](clients.md) lists removal commands. Verify that its tools disappear. This removes the local configuration; it does not revoke VTAI access or delete VTAI history. A new OAuth connection does not inherit the original connection's receipts.

Do not remove a credential file shared by other clients unless you intend to remove their local access too. After a local disconnect, a still-valid credential can be used to reconnect without registering again.

## Revoke access

For an Agent Token, use the [revocation form](https://ai.virustotal.com/connect/mcp?client=other&transport=http&auth=token#revoke). Enter the credential in that human-facing form and confirm the action. Its API is `DELETE /api/v3/agents/me/token`, authenticated with one `Authorization: Bearer` or `x-apikey` header; this is an access-management operation, not an MCP tool. For OAuth, use [Your connections](https://ai.virustotal.com/oauth/connections) instead. Recover uncertain submissions before revoking their connection when possible.

A confirmed revocation returns 204. A timeout or service error does not confirm success; retain protected access to the credential so you can diagnose or retry. A 401/403 means it was not accepted, not proof that this particular action revoked it.

VTAI currently has one credential per agent. Revocation disables that agent across clients, REST and MCP; records remain, and a lookup admitted before revocation may finish. Remove the connection from every affected client afterward. To obtain access after revocation, explicitly register a new agent. This is not rotation of the old agent's credential.

A subsequent request using the revoked token receives 401 with Bearer or 403 with legacy `x-apikey`; the two headers do not create separate credentials.
