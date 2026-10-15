# Connect an MCP client

For automatic setup on Linux, macOS or Windows, choose your system in the [setup guide](https://ai.virustotal.com/connect/mcp). Manual shell examples below use POSIX syntax. Native package tests cover file handling and MCP protocol behavior; historical client/model validation keeps its original platform and version scope.

Current setup targets **vt-mcp 0.9.9** and the compatible VTAI service. Ten common tools cover four report lookups, `get_analysis`, `get_submission`, `submit_file`, `submit_url`, `reanalyze_domain` and `reanalyze_ip`. The hosted service advertises eleven tools, adding `submit_attachment` for an original file available through a public HTTPS download URL. Native attachment transfer depends on the client. Local stdio instead adds `submit_local_file` for eleven local tools. HTTP needs no local Python installation and supports an Agent Token or browser OAuth; stdio uses the installed package and an Agent Token. Inline file submission accepts up to 24,000,000 decoded bytes; local file submission accepts up to 32,000,000 bytes. See [installation](../README.md#install-for-local-stdio) and [submission and recovery](analysis.md).

The current instructions were synchronized on 2026-10-03. Dated validation records below retain their original client versions, tools and transport scope; they do not certify every current tool in each client. OAuth network writes require `vt:reports:read` plus `vt:network-analysis:write`; existing file-write grants do not expand automatically. Reconnect to approve that permission when needed. Host tool permissions and OAuth scopes are separate.

Submission tools have no per-call human confirmation or consent argument. Configure the specific host permissions for files, URLs and network indicators you authorize for standard sharing; host permissions still apply. **The 0.8 submission cycle has been exercised in staging and against a production candidate. The public rollout is accepted, with separate direct SDK checks.** The [historical native-client validation](client-validation-2026-09-07.md) covers five read-only tools in 0.7, not autonomous submission. Set up protected access using the [access guide](access.md), or the [README](../README.md#connect-your-client).

VT-MCP provides the submission capability. Use it only when the user explicitly requests the submission or reanalysis; host permissions also apply. Agy, Claude Code and Codex have separate authorization policies. A tool appearing in discovery is not an approval, and a host prompt or denial is not a new VT-MCP consent requirement. The client-specific grants below preserve that distinction.

Start with [Antigravity CLI (`agy`)](#antigravity-cli-agy), [Claude Code](#claude-code), or [Codex CLI](#codex-cli--remote-http). Other client guides follow those three.

VTAI 0.8.1 adds static Bearer authentication as an alternative to `x-apikey`, using the same VTAI token, rights and quotas. The current stdio wrapper continues using `x-apikey`; the historical MIT distribution remains at 0.8.0. Send only one credential method per connection. The [scoped Bearer checks and deployment status](#bearer-authentication-validation) are separate from the historical `x-apikey` workflow evidence. See [authentication and diagnostics](access.md#choose-one-authentication-header).

## Antigravity CLI (`agy`)

For a native remote connection with browser sign-in, see the
[Antigravity OAuth recipe](google-clients.md#antigravity-native-oauth). Its current
validation is separate from the tested stdio setup below.

Use your native Antigravity login, then install the verified vt-mcp wheel and configure its credential-file path:

```bash
agy mcp add --env VTAI_TOKEN_FILE="$HOME/.config/vt-mcp/token" virustotal vt-mcp
```

Flags must precede the server name. Use an absolute executable path if needed. CLI 1.1.27 saved this entry in `~/.gemini/config/mcp_config.json`; its fields match [stdio.json](../examples/client-configs/stdio.json). Restart `agy` and inspect `/mcp`. Remove it with `agy mcp remove virustotal`. The native model login is separate from VTAI access; this setup does not require Vertex or ADC. [Official MCP documentation](https://antigravity.google/docs/cli/mcp/).

For the current local tools, merge only the permissions your task needs into `permissions.allow` in `~/.gemini/antigravity-cli/settings.json`, preserving existing settings. The eleven names below include optional file and network writes. For read-only access, omit `submit_file`, `submit_local_file`, `submit_url`, `reanalyze_domain` and `reanalyze_ip`. Keep the three network-write entries only for tasks that permit standard sharing of those indicators:

```json
{
  "permissions": {
    "allow": [
      "mcp(virustotal/get_file_report)",
      "mcp(virustotal/get_url_report)",
      "mcp(virustotal/get_domain_report)",
      "mcp(virustotal/get_ip_report)",
      "mcp(virustotal/get_analysis)",
      "mcp(virustotal/get_submission)",
      "mcp(virustotal/submit_file)",
      "mcp(virustotal/submit_local_file)",
      "mcp(virustotal/submit_url)",
      "mcp(virustotal/reanalyze_domain)",
      "mcp(virustotal/reanalyze_ip)"
    ]
  }
}
```

Existing deny or ask rules take precedence over allow rules. Select a model available to your account with `agy models`; `agy -p 'Query the existing VirusTotal report for example.com and show its source, analysis date and coverage.'` runs a single prompt. A successful process exit alone does not prove that a tool ran: check the returned report or `--output-format stream-json` events. [Permissions](https://antigravity.google/docs/cli/permissions/), [headless execution](https://antigravity.google/docs/cli/headless/).

The eleven names above describe the current local server contract. Agy exercised the three-tool submission, receipt and analysis cycle in [staging and a production candidate](#version-08-submission-evidence); this historical run does not establish calls to all eleven current tools. `get_analysis` and `get_submission` do not upload. agy can save a long tool result in its own generated output file; the historical analysis workflow used `view_file` to read that result. MCP grants do not prevent unrelated host tools from running or authorize arbitrary file disclosure.

With v0.7.0, CLI 1.1.27 completed all five read-only tools through stdio with its native login. A separate loopback test found that `$VAR`, `${VAR}` and `${env:VAR}` in HTTP headers were sent literally. Use the protected token-file stdio setup for this version; production HTTP remains unvalidated. See the [session evidence and limits](client-validation-2026-09-07.md).

## Claude Code

Sign in with your existing Claude subscription using `claude auth login --claudeai` (or `/login` inside Claude Code). Vertex and ADC are optional cloud-provider choices, not vt-mcp requirements. This model-provider login is separate from your VTAI credential. [Claude Code authentication](https://code.claude.com/docs/en/authentication).

```bash
claude mcp add --env VTAI_TOKEN_FILE="$HOME/.config/vt-mcp/token" \
  --scope user --transport stdio virustotal -- vt-mcp
```

For HTTP, merge [claude-http.json](../examples/client-configs/claude-http.json) into a project `.mcp.json` you control and launch Claude Code with `VTAI_MCP_TOKEN` using the [protected-file launch instructions](access.md#remote-client-environment). Its `${VAR}` header expansion was exercised in the production workflow below. Do not pass an expanded credential to `--header`: it may expose the value in process arguments or configuration.

For the **Bearer alternative on VTAI 0.8.1**, use this entry instead of the fragment's `x-apikey` entry. Preserve unrelated servers and permissions, and remove any `x-apikey` header from this server. Load the same protected environment variable before launching:

```json
{
  "mcpServers": {
    "virustotal": {
      "type": "http",
      "url": "https://ai.virustotal.com/mcp",
      "timeout": 180000,
      "headers": {
        "Authorization": "Bearer ${VTAI_MCP_TOKEN}"
      }
    }
  }
}
```

Claude Code documents environment expansion in `headers`; the text above is a reference, not a token value. This does not configure a Claude hosted connector or VTAI OAuth. [Official environment expansion](https://code.claude.com/docs/en/mcp). The [Bearer native checks](#bearer-authentication-validation) used this mechanism through QA proxies.

Inspect `/mcp` inside the launched Claude Code session. If you run `claude mcp list` separately for an environment-based HTTP entry, launch it with the same protected token environment; a separate terminal does not inherit another session’s variables. Remove the stdio user entry with `claude mcp remove --scope user virustotal`. Remove the HTTP project entry from `.mcp.json` or use `claude mcp remove --scope project virustotal`, then restart/reload. The scope/transport options terminate the variadic `--env` option in the command above. CLI 2.1.257 help was checked on 2026-09-06 and 2.1.263 help on 2026-09-07. This setup is separate from a claude.ai connector. [Official Claude Code MCP documentation](https://code.claude.com/docs/en/mcp).

For a per-run connection, save an adjusted [stdio fragment](../examples/client-configs/stdio.json) in a local file and pass `--strict-mcp-config --mcp-config /absolute/path/vt-mcp.json`. This loads only the specified MCP configuration while preserving your native login. For unattended reports, `--allowedTools` accepts the four exact names `mcp__virustotal__get_file_report`, `mcp__virustotal__get_url_report`, `mcp__virustotal__get_domain_report` and `mcp__virustotal__get_ip_report` as a comma-separated list. The verified run used those grants with `--permission-mode dontAsk`, `--tools ""` and `--print --verbose --output-format stream-json`. Inspect tool results and permission denials as well as the final response. [Claude Code permissions](https://code.claude.com/docs/en/permissions).

For report reads, file submission and receipt recovery, use these exact grants as the comma-separated `--allowedTools` value; omit `submit_file` for read-only access:

```text
mcp__virustotal__get_file_report,mcp__virustotal__get_url_report,mcp__virustotal__get_domain_report,mcp__virustotal__get_ip_report,mcp__virustotal__get_analysis,mcp__virustotal__get_submission,mcp__virustotal__submit_file
```

For authorized URL submission and domain/IP reanalysis, append these optional grants to the same comma-separated value:

```text
mcp__virustotal__submit_url,mcp__virustotal__reanalyze_domain,mcp__virustotal__reanalyze_ip
```

For **stdio only**, append `mcp__virustotal__submit_local_file` when local file submission is needed. Remote HTTP tools do not read a local path. Keep `--permission-mode dontAsk`, `--tools ""` and the explicit MCP configuration if using the previously documented unattended pattern; a denied tool is a permission failure, not successful completion. Do not replace specific grants with a general permission bypass. The three-tool 0.8 submission cycle ran with specific grants through both transports in [staging and a production candidate](#version-08-submission-evidence). The accepted public rollout has separate direct SDK evidence below. The same per-run configuration flags accept the HTTP fragment. In the historical v0.7.0 sessions, CLI 2.1.263 completed all five read-only tools through stdio and public HTTP using a native Claude subscription. The runs used a terminal PTY; this observation does not establish that PTY is required. See the [session evidence](client-validation-2026-09-07.md).

## Codex CLI — remote HTTP

With v0.7.0, Codex CLI 0.153.4 completed all five read-only tools in separate public HTTP and stdio sessions with `gpt-6-astra` / `xhigh` requested. The [validation matrix](#validation-levels) records these separately from historical report-only sessions, guard behavior and release acceptance. Use the [versioned installation instructions](../README.md#install-for-local-stdio) and verify the artifact associated with the selected release.

Merge this entry into `~/.codex/config.toml`, preserving other settings. Replace an existing `virustotal` stdio entry instead of combining `command` and `url` or registering twice.

```toml
[mcp_servers.virustotal]
tool_timeout_sec = 180
url = "https://ai.virustotal.com/mcp"

[mcp_servers.virustotal.env_http_headers]
x-apikey = "VTAI_MCP_TOKEN"
```

`VTAI_MCP_TOKEN` is an environment-variable name, not a credential value. In your own Bash terminal, start Codex from the protected file:

```bash
(
  set +x
  unset VTAI_MCP_TOKEN
  IFS= read -r VTAI_MCP_TOKEN < "$HOME/.config/vt-mcp/token" || test -n "$VTAI_MCP_TOKEN" || exit 1
  test -n "$VTAI_MCP_TOKEN" || exit 1
  export VTAI_MCP_TOKEN
  exec codex
)
```

This also accepts a nonempty credential file without a trailing newline. A missing file or an empty first line prevents launch. The subshell avoids leaving a new export in your parent shell. An already running app or a desktop launcher may not inherit this environment; close and restart the selected client through the configured launch path. Do not ask the model to read the file or environment.

The `env_http_headers` mapping is documented in [official Codex MCP configuration](https://learn.chatgpt.com/docs/extend/mcp), accepted by the checked CLI 0.153.4 schema and used in the production workflow recorded below. It remains supported.

For the **Bearer alternative on VTAI 0.8.1**, use this HTTP entry instead of the first example. Remove the existing `x-apikey` mapping from `env_http_headers` or `http_headers`; do not combine the two authentication methods. Preserve your other settings and any specific tool-approval tables:

```toml
[mcp_servers.virustotal]
tool_timeout_sec = 180
url = "https://ai.virustotal.com/mcp"
bearer_token_env_var = "VTAI_MCP_TOKEN"
```

Codex reads the variable named by `bearer_token_env_var` and sends `Authorization: Bearer` with its value. The same protected-file Bash launch above supplies it. No token belongs in the TOML, command arguments or model prompt. `codex mcp login` is an OAuth flow; it does not obtain a VTAI Agent Token. [Official Bearer setting](https://learn.chatgpt.com/docs/extend/mcp), [configuration reference](https://learn.chatgpt.com/docs/config-file/config-reference). The [Bearer native checks](#bearer-authentication-validation) used this mechanism through QA proxies.

Restart and inspect `/mcp`, then [check the tools](#try-the-tools). Remove the connection with `codex mcp remove virustotal` and restart. Reuse the same active VTAI credential if you reconnect.

Current HTTP discovery should list the four reports plus `get_analysis`, `get_submission`, `submit_file`, `submit_url`, `reanalyze_domain` and `reanalyze_ip`. Authorize those specific MCP operations through your normal host policy for the assigned task; the server does not add a per-call confirmation. Do not disable unrelated host safeguards. `submit_local_file` is absent over HTTP. The three-tool 0.8 workflow was exercised in [staging and a production candidate](#version-08-submission-evidence). The accepted public rollout has separate direct SDK evidence below.

For persistent authorization of the HTTP submission tool, use the [per-tool approval setting](#codex-approval-for-submission-tools) below.

## Codex CLI — local stdio

Install the verified wheel first. Use an absolute executable path if `vt-mcp` is absent from the client's PATH. The command passes a credential-file path, not its contents:

```bash
codex mcp add virustotal --env VTAI_TOKEN_FILE="$HOME/.config/vt-mcp/token" -- vt-mcp
```

After adding the local server, set `tool_timeout_sec = 180` under `[mcp_servers.virustotal]` in `~/.codex/config.toml`, or use the [stdio configuration fragment](../examples/client-configs/codex-stdio.toml). This covers the 150-second local submission budget; Codex otherwise defaults to 60 seconds per tool. [Official timeout setting](https://learn.chatgpt.com/docs/extend/mcp).

Current local discovery should additionally include `submit_local_file`, for eleven tools. The path belongs to the local vt-mcp process; its optional expected SHA-256 must match the copied bytes. Allow this specific tool only for authorized standard-sharing tasks. Restart Codex and use `/mcp` to inspect the integration. Remove it with `codex mcp remove virustotal`. The command syntax was checked against Codex CLI `0.153.4` and [official OpenAI documentation](https://learn.chatgpt.com/docs/extend/mcp) on 2026-09-06.

### Codex approval for submission tools

For tasks you authorize for standard sharing, merge the matching table into your
existing `~/.codex/config.toml`. Use your configured server name in place of
`virustotal` if different. Preserve the other tools, server defaults and host
settings; select only the tool-specific approvals needed for your task.

For local stdio:

```toml
[mcp_servers.virustotal.tools.submit_local_file]
approval_mode = "approve"
```

For remote HTTP:

```toml
[mcp_servers.virustotal.tools.submit_file]
approval_mode = "approve"
```

For network analysis over either transport, optional tool-specific tables are:

```toml
[mcp_servers.virustotal.tools.submit_url]
approval_mode = "approve"

[mcp_servers.virustotal.tools.reanalyze_domain]
approval_mode = "approve"

[mcp_servers.virustotal.tools.reanalyze_ip]
approval_mode = "approve"
```

Omit those tables for read-only tasks. These apply the same per-tool setting to the new names; the historical native validation below covered the file tools, not network writes. With OAuth, the connection also needs the network-write scope.

`enabled_tools` is a separate allowlist of exposed names, not an approval grant.
If you use it, the intended submission tool, `get_submission` and `get_analysis`
must be available for the full cycle; `disabled_tools` still takes precedence.
Do not replace the server-wide approval default or disable unrelated host controls.
The setting does not restrict which file or network arguments are authorized or enlarge VTAI
rights. [Official MCP settings](https://learn.chatgpt.com/docs/extend/mcp),
[configuration reference](https://learn.chatgpt.com/docs/config-file/config-reference).

Both file-tool approval fragments were exercised with Codex CLI 0.153.4 in the
[0.8 staging and production-candidate workflows](#version-08-submission-evidence),
without per-call approval prompts. These native sessions retain their candidate-route
scope; the accepted public rollout and direct SDK checks are separate observations.

## Cursor

Merge [cursor-http.json](../examples/client-configs/cursor-http.json) into
`~/.cursor/mcp.json` for your user, or `.cursor/mcp.json` in a trusted project.
Load `VTAI_MCP_TOKEN` from the protected token file before launching the client,
using the [environment instructions](access.md#remote-client-environment).
In that Bash example, replace `exec claude` with your Cursor executable, or
`exec agent` for Cursor CLI. Close an existing GUI process before relaunching.
The reference `${env:VTAI_MCP_TOKEN}` belongs in the configuration; the token does
not. Restart the application through that launch environment and enable the
server in its MCP settings. Cursor documents this expansion in HTTP headers;
VS Code's `${input:...}` syntax is not part of this recipe.
[Cursor MCP documentation](https://cursor.com/docs/mcp).

Cursor CLI uses the editor's MCP configuration. Inspect it with `agent mcp list`
and `agent mcp list-tools virustotal`. CLI discovery is separate from an IDE
model session. To disconnect, remove the `virustotal` entry from the file where
you added it and reload. [Cursor CLI MCP](https://cursor.com/docs/cli/mcp).

**Status:** Cursor CLI `2026.09.10-fd3934a` expanded the environment reference
and completed two native discovery commands against a local HTTP server.
Successful POST discovery was observed after GET 405 responses. Cursor IDE,
tool calls and a model workflow against VTAI remain unverified.

## VS Code with GitHub Copilot

Merge [vscode-http.json](../examples/client-configs/vscode-http.json) into
`.vscode/mcp.json`, or open **MCP: Open User Configuration** for your profile.
This format uses `servers` and `inputs`. Start `virustotal` through **MCP: List
Servers** and enter your VTAI Agent Token in the password input, outside chat.
Keep `${input:vtai-token}` in the JSON. VS Code documents retaining the input for
later starts. Remove the server entry from the selected configuration and stop
it through the same command to disconnect.
[VS Code configuration reference](https://code.visualstudio.com/docs/agents/reference/mcp-configuration).

This input-based recipe targets VS Code's Extension Host. Current VS Code
documentation says servers requiring interactive inputs are not forwarded to
the Agent Host. For that runtime or Copilot CLI, use the separate Copilot format
below; `.vscode/mcp.json` and `~/.copilot/mcp-config.json` are not interchangeable.
[VS Code MCP setup](https://code.visualstudio.com/docs/agent-customization/mcp-servers).

**Status:** VS Code 1.107.1 completed native HTTP tool calls against a local
server, including password input resolution, GET 405 handling and restart.
A VS Code Copilot model workflow against VTAI remains unverified. See the
[additional-client matrix](#additional-client-validation) for the scope.

## GitHub Copilot CLI

Install the [verified local package](../README.md#install-for-local-stdio), then
merge [copilot-cli-stdio.json](../examples/client-configs/copilot-cli-stdio.json)
into `~/.copilot/mcp-config.json`. Alternatively, add it from your terminal:

```bash
copilot mcp add virustotal --env VTAI_TOKEN_FILE="$HOME/.config/vt-mcp/token" --timeout 180000 -- vt-mcp
```

This passes a file path, never the credential. The fragment uses `mcpServers`
and `type: "local"`; `vt-mcp` expands its own token-file path. Use an absolute
executable path if it is absent from the client's PATH. Inspect with
`copilot mcp get virustotal`; remove with `copilot mcp remove virustotal`.
The `tools` list controls availability, while Copilot's permissions control
execution. Your Copilot login is separate from VTAI access.
[Copilot CLI MCP documentation](https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/add-mcp-servers).

**Status:** CLI 1.0.83 used a model to call `get_domain_report` for
`virustotal.com` through the public vt-mcp 0.8.0 stdio package and used the
`found` response from VTAI. This validates that domain lookup workflow; other
tools and remote HTTP workflows have not been validated with this client.

## Devin Local and Windsurf / Devin Desktop

Select instructions for the agent running inside the editor. **Devin Local and
legacy Cascade use separate recipes.** Open the configuration for that agent.

For **Devin Local / Devin CLI**, install the verified local package and merge
[stdio.json](../examples/client-configs/stdio.json) into
`~/.config/devin/mcp_config.json`, or `.devin/mcp_config.local.json` for a local
project configuration. These dedicated MCP files apply from CLI v3000.3 /
Local 3.6; earlier versions used `config*.json`. The fragment supplies the path
to the token file; `vt-mcp` reads it. This avoids relying on unverified HTTP
header interpolation in Devin Local.
[Devin configuration reference](https://docs.devin.ai/cli/reference/configuration/config-file).

For **legacy Cascade** in Windsurf / Devin Desktop, open **MCP Servers** from
Cascade and open its raw configuration file. Merge
[cascade-http.json](../examples/client-configs/cascade-http.json) into the file
your version opens, preserving existing settings, then refresh the MCP servers.
The documented legacy path is `~/.codeium/windsurf/mcp_config.json`; Devin Desktop
3.10.23 on Linux opened `~/.config/devin/mcp_config.json`. Use the app's action
to select the file instead of adding entries to both paths. This observation
does not establish migration or exclusive use of either path.

Its documented `${file:~/.config/vt-mcp/token}` expansion reads and trims the
file. Store only the VTAI token there, without `Bearer` or dotenv syntax. An
unreadable file leaves the reference unresolved. Cascade documents both
`serverUrl` and `url`; this fragment uses `serverUrl`.
[Cascade MCP](https://docs.devin.ai/desktop/cascade/mcp).

Devin can also import other editors' MCP configuration. Check the effective
source to avoid duplicate entries; remove the entry from that source and reload
to disconnect. [Configuration imports](https://docs.devin.ai/cli/reference/configuration/read-config-from).

**Status:** Devin CLI 3000.10.21 launched vt-mcp 0.8.0 over stdio through ACP
and initialized the server. This does not validate loading the dedicated MCP
configuration file, tool discovery, tool calls or a model workflow against VTAI.
The Cascade configuration editor was opened in Devin Desktop 3.10.23 on Linux;
HTTP transport, file-token expansion and tool/model workflows remain unverified.

## Gemini Apps

Use the [Gemini Apps custom MCP connection and optional skill](google-clients.md#gemini-apps-custom-connection).
The guide covers eligibility, browser consent, importing `SKILL.md`, a report-only
check and removal. Its validation is distinct from Gemini CLI and Antigravity.

## Gemini CLI

The [Gemini CLI extension](google-clients.md#gemini-cli-extension) adds the hosted
server with OAuth, without a local Python process or static token. Native extension
installation and loading were checked with CLI 0.58.0; OAuth and model workflows
remain separate. The manual static-token alternatives below remain available.

Google retired Gemini CLI access through **Sign in with Google** for Gemini Code Assist for individuals, Google AI Pro and Google AI Ultra on 2026-06-18. Use [Antigravity CLI (`agy`)](#antigravity-cli-agy) for those accounts. Standard and Enterprise are unaffected by that retirement; Gemini API-key authentication is a separate option. These remaining routes require their own account and model checks. [Official retirement notice](https://developers.google.com/gemini-code-assist/docs/deprecations/code-assist-individuals), [Gemini authentication](https://geminicli.com/docs/get-started/authentication/).

```bash
gemini mcp add --env VTAI_TOKEN_FILE="$HOME/.config/vt-mcp/token" \
  --scope user --transport stdio virustotal vt-mcp
```

For HTTP, merge [gemini-qwen-http.json](../examples/client-configs/gemini-qwen-http.json) into `~/.gemini/settings.json` and provide `VTAI_MCP_TOKEN` when launching Gemini. `httpUrl` selects Streamable HTTP; `url` denotes older SSE.

Restart and inspect `/mcp` or `gemini mcp list`. Remove with `gemini mcp remove --scope user virustotal`. Workspace trust can affect connection. Explicitly declare the stdio `env` entry: Gemini filters inherited sensitive names, including TOKEN. CLI 0.38.1 help and its installed environment resolver were checked on 2026-09-06; that is not an HTTP tool-call test. [Official Gemini MCP documentation](https://geminicli.com/docs/tools/mcp-server/).

## Antigravity IDE

Open **MCP Servers → Manage MCP Servers → View raw config** in the agent panel and merge [stdio.json](../examples/client-configs/stdio.json). Use an absolute executable path if needed, then reload and inspect the manager. Remove the entry or set `disabled: true` to disconnect.

The tested IDE is `1.20.6`; its CLI/base reports `1.107.0`, commit `135ccf460c67c4b900dc10aa71c978f27d78601c`, x64. Its bundled schema accepts `command`, `args`, `env`, `serverUrl`, `headers`, `disabled` and `disabledTools`. Current online documentation includes newer paths and fields rejected by that installed schema. Use **View raw config** to locate the file; do not apply the Gemini CLI path by analogy.

Safe HTTP-header environment expansion was not established for this version. The
stdio token-file setup retains its report workflow evidence below. For a remote
connection without a static header, use the [native OAuth recipe](google-clients.md#antigravity-native-oauth),
with its separate validation limits. [Official Antigravity MCP documentation](https://antigravity.google/docs/mcp).

If discovery succeeds but lookups return `unavailable`, check the MCP process's HTTPS configuration. In the tested Linux environment, Antigravity supplied an incomplete `SSL_CERT_FILE` bundle. Setting `SSL_CERT_FILE` to `/etc/ssl/certs/ca-certificates.crt` in this server's `env` and reloading resolved certificate verification errors. Use the trusted CA bundle appropriate to your machine; this Linux path is not portable. TLS verification remained enabled and proxy settings were preserved.

## DeepSeek Harness

Install the [DSH plugin](../plugins/dsh/README.md) to add the hosted server, a
`virustotal-threat-intelligence` skill and a `virustotal_submit_local_file` tool to
DeepSeek Harness. The DSH MCP client supports `stdio` and `streamable-http` with
static headers but has **no OAuth flow**, so this client cannot use the browser
sign-in documented for Claude Code, Antigravity and Gemini CLI. The plugin instead
sends a static `x-apikey` header whose value it reads at startup from a protected
token file (`~/.config/vt-mcp/token`, or the path named by `VTAI_TOKEN_FILE`). The
token is not stored in the plugin, in this repository or in the conversation.
Follow the [plugin README](../plugins/dsh/README.md) for the credential steps, the
tested configuration and the local stdio alternative.

Ask the plugin's own skill for a report-only check once the tools appear:

> Use VirusTotal to retrieve the existing report for `virustotal.com`. Show the
> source, analysis date, coverage and report link. Do not request a new analysis.

**Status:** Bundle installation and activation, skill registration, the
missing-credential failure mode, discovery of the eleven hosted tools,
`get_domain_report`, `get_url_report` and `get_file_report` calls, and a
disable/enable cycle were verified on Windows with DSH Desktop 2.0.17 on
2026-10-15. The plugin's own `virustotal_submit_local_file` tool was verified
against the live server in the same period, including every refusal path and a
650,752-byte transfer of an already-known file, which published nothing new; it
appears in a running session only after a Harness restart, because a profile
bundle caches its imported module. A genuinely new upload, reanalysis and receipt
recovery were not exercised. Over HTTP `submit_local_file` is absent; the plugin
supplies its own equivalent rather than an upload hook.

## Qwen Code

Proposed command, documented but not executed here:

```bash
qwen mcp add --env VTAI_TOKEN_FILE="$HOME/.config/vt-mcp/token" \
  --scope user --transport stdio virustotal vt-mcp
```

The [stdio fragment](../examples/client-configs/stdio.json) fits `mcpServers` in `~/.qwen/settings.json`. For HTTP, use [gemini-qwen-http.json](../examples/client-configs/gemini-qwen-http.json) with the host environment variable. Inspect `/mcp` or `qwen mcp list`; remove with `qwen mcp remove virustotal`.

Qwen was not installed. Field types and the recursive environment resolver were inspected at source commit `42481176c5e3c49911d4cc07a6d1e569312d0cf7`. Its published settings schema is permissive inside `mcpServers`; acceptance alone does not validate those fields. Parser, connection and model workflow remain pending. [Official Qwen MCP documentation](https://qwenlm.github.io/qwen-code-docs/en/users/features/mcp/).

## Kimi Code CLI

Proposed command, documented but not executed here:

```bash
kimi mcp add --env VTAI_TOKEN_FILE="$HOME/.config/vt-mcp/token" \
  --transport stdio virustotal -- vt-mcp
```

Alternatively merge [stdio.json](../examples/client-configs/stdio.json) into `~/.kimi/mcp.json`. Inspect `/mcp` or `kimi mcp test virustotal`; remove with `kimi mcp remove virustotal`. `--mcp-config-file` can load a separate configuration file.

Kimi was not installed. Source commit `86f136422a0aae6b217ea49e7ea1d2e8a1defcd2` declares Kimi 1.50.0 and FastMCP 3.2.4. Its loader/field definitions were inspected; safe environment expansion in HTTP headers was not established. Use stdio rather than another client's interpolation syntax. [Official Kimi MCP documentation](https://github.com/MoonshotAI/kimi-cli/blob/86f136422a0aae6b217ea49e7ea1d2e8a1defcd2/docs/en/customization/mcp.md).

## OpenCode and model providers

For OpenCode **V1**, merge [opencode-v1-stdio.json](../examples/client-configs/opencode-v1-stdio.json) or [opencode-v1-http.json](../examples/client-configs/opencode-v1-http.json) into `~/.config/opencode/opencode.json`. HTTP uses `{env:VTAI_MCP_TOKEN}` and disables OAuth auto-detection. Inspect `opencode mcp list`; remove the entry or set `enabled: false`, then restart.

OpenCode was not installed. On 2026-09-06, its [public schema](https://opencode.ai/config.json) accepted the V1 fragments but rejected the different nesting in its [V2 documentation](https://opencode.ai/v2/docs/mcp-servers). V2 remains pending a pinned binary/parser test. [Official V1 MCP documentation](https://opencode.ai/docs/mcp-servers/).

Applications using **Z.ai or DeepSeek** can reuse these MCP settings. Configure the model provider separately in OpenCode's credential interface. Z.ai documents `opencode auth login` with Z.AI or Z.AI Coding Plan, then `/models`. OpenCode documents `/connect` for DeepSeek and `/models` for model selection. Enter provider keys in that credential interface, never VTAI settings or chat. Neither provider flow was exercised here. [Z.ai with OpenCode](https://docs.z.ai/devpack/tool/opencode), [OpenCode DeepSeek setup](https://opencode.ai/docs/providers/#deepseek).

These are application integrations, not claims that Z.ai/DeepSeek chat websites directly accept this MCP. No provider-specific server or SDK is required.

## ChatGPT and Claude hosted connectors

For ChatGPT, [install the published VirusTotal plugin](https://chatgpt.com/plugins/plugin_asdk_app_6abadac2d9a08191ae2307c047bb3806), connect with Google when prompted, and select `@VirusTotal` in a new chat. Developer mode is not required for this published-plugin route; availability still depends on account and workspace policies. The [ChatGPT setup guide](hosted-clients.md#connect-chatgpt-work) also documents the separate custom-app route for accounts that permit Developer mode. ChatGPT web does not load local Codex configuration. [OpenAI plugin guide](https://learn.chatgpt.com/docs/plugins).

VTAI provides OAuth separately from static token headers and supports DCR and CIMD. On 2026-09-24, ChatGPT Work completed personal OAuth consent, returned an IP report through the production MCP server, then automatically renewed its token and returned a subsequent report after the previous token had expired. These runtime checks are separate from the published directory listing and did not cover revocation from the hosted application, incremental authorization or writes. A VTAI token is not an OAuth client secret. See [OAuth compatibility](hosted-clients.md#oauth-compatibility) and [OpenAI authentication requirements](https://developers.openai.com/plugins/build/auth).

Claude remote connectors are separate from Claude Code and local Claude Desktop MCP. Documented remote plans include Free, Pro, Max, Team and Enterprise; Free has one custom connector, and Team/Enterprise require an Owner to add one. Requests originate from Anthropic infrastructure even when using Desktop. Account permissions and connectivity still need testing. [Claude remote connector requirements](https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp).

Claude's fixed-header organization beta can use VTAI Bearer when an eligible organization deliberately shares one identity, quota and submission ownership. The [hosted setup guide](hosted-clients.md) documents that option and its acceptance query; it has not been tested in a hosted account. VTAI OAuth is live; a Claude hosted account and model workflow remain unverified. An OAuth client secret is not universally required. [Claude authentication](https://claude.com/docs/connectors/building/authentication), [request-header beta](https://claude.com/docs/connectors/custom/remote-mcp#authenticating-with-request-headers).

## Try the tools

Current discovery has eleven hosted HTTP tools (including the client-neutral
attachment adapter), or eleven local stdio tools (including `submit_local_file`). For an
existing report, use the read-only examples below. For a file submission explicitly
requested by the user, use `submit_file` with SHA-256 and base64 bytes, or local stdio `submit_local_file`
with its path. Follow the [autonomous workflow](analysis.md#autonomous-mcp-workflow):
keep the SHA-256, recover with `get_submission` if needed, and read the returned
analysis ID. A tool invocation is not proof of upload or completion: inspect
`exists`, `submitted`, `submission_unknown`, `pending` and `completed` faithfully.
Do not repeat submission to resolve an ambiguous response.

For an authorized network operation, generate and persist a lowercase UUIDv4 before calling `submit_url`, `reanalyze_domain` or `reanalyze_ip`. Recover with `get_submission(request_id=request_id)` using the same connection, then read `get_analysis(analysis_id, request_id=request_id)`. Do not generate a new ID to resolve uncertainty. Follow the [network workflow](analysis.md#network-analysis-and-recovery), including standard sharing, rejected receipts and finite polling.

For a first query, ask: “Use VirusTotal to get the domain report for virustotal.com. Show the source, analysis date, coverage and report link.” In ChatGPT, prefix the prompt with `@VirusTotal`. For file regression, use the SHA-256 of the empty file: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

Ask for the source, analysis date and coverage, with missing data stated explicitly. A 404 is a valid unknown result. These lookups send no explicit analysis POST from VTAI; VirusTotal controls upstream processing. A URL query discloses the complete URL to VTAI and VirusTotal; use domain scope when sufficient. Removing a client configuration does not revoke the VTAI credential.

To read a selected analysis, use the exact `analysis_id` returned by an authorized [submission or recovery](analysis.md) through the same Agent Token or OAuth connection. Preserve the ID, status, analysis date and coverage, plus the file SHA-256 or network request ID. For network analyses, pass `request_id` to `get_analysis` to select the intended receipt. A completed analysis is not a safety verdict; an existing report is not a substitute for that selected analysis.

## Connection problems

| Observation | Action |
|---|---|
| `/mcp` or `/connect/mcp` is unavailable | Check deployment availability and the exact service URL/prefix; do not treat this as an unknown indicator |
| 400 / Bearer `invalid_request` | Correct malformed/repeated Bearer authentication or remove the extra `x-apikey` mapping; use one credential method |
| 401 | A supported credential is missing or the Bearer token was rejected; check environment, expiry and revocation without displaying the value |
| 403 | Legacy `x-apikey` was rejected or an operation was denied after authentication; inspect the structured error and reuse valid access instead of registering automatically |
| 429 | Wait for the supplied retry delay; REST and MCP share the agent's query quota |
| Tool error or timeout | Read the structured error without exposing credentials; a service failure is not a safety verdict |

The optional check on the [Agent Token page](https://ai.virustotal.com/connect/mcp?client=other&transport=http&auth=token#access-heading) calls `GET /api/v3/agents/me/access` without consuming query quota. It checks authentication, not a report or your model's use of MCP. Confirm tool discovery and one explicit report call in the client separately; that report consumes quota. For stdio startup failures, inspect PATH and stderr; stdout belongs to MCP.

Use the [Agent Token revocation form](https://ai.virustotal.com/connect/mcp?client=other&transport=http&auth=token#revoke) or authenticated `DELETE /api/v3/agents/me/token` when required. Only HTTP 204 confirms that revocation; clearing the page or deleting client settings does not. For OAuth use [Your connections](https://ai.virustotal.com/oauth/connections). Recover any uncertain submission through its original connection before removing it. Revocation disables that credential across REST and MCP, while an already admitted request may finish. Keep a protected copy while the revocation outcome is unconfirmed.

## Validation levels

### Current browser OAuth and Google scope

Reconciled on 3 October 2026. These observations are separate from the historical
Agent Token, local transport and submission records below.

| Client | Verified observation | Remaining scope |
|---|---|---|
| Claude Code 2.1.284 / plugin 0.1.3, Linux, 1 Oct | Fresh plugin OAuth; reports, one file upload, network analysis and receipt recovery | Authenticated Windows/macOS uploads and hosted Claude chat; see [plugin validation](claude-code.md#validation-and-removal) |
| ChatGPT Work, 24 Sep | Browser consent, IP reports and automatic token renewal | Hosted revocation, incremental permissions and writes; see [hosted validation](hosted-clients.md#validation-scope) |
| Claude web / Desktop | Existing claude.ai connection imported and used in Claude Code on 28 Sep | No hosted chat report, renewal or write workflow is established by that imported connection |
| Antigravity CLI 1.2.14/1.2.15, 2 Oct | Plugin installation, native OAuth, one domain report and revocation | Manual `serverUrl` entry, renewal, writes and graphical IDE OAuth; see [Google validation](google-clients.md#validation-and-discovery) |
| Gemini CLI 0.58.0, 2 Oct | OAuth extension 0.9.8 installation/skill discovery; separate domain query with supplied Bearer and Gemini API-key model access | Native browser OAuth and renewal; extension and skill were disabled during the query |
| Gemini Apps, 3 Oct | Manual skill import appeared under Active | MCP login, report query, renewal and writes; skill import does not enable Custom apps |
| Cursor, VS Code, Copilot CLI, Devin Local / CLI | OAuth setup documented by each client | VTAI browser OAuth and model query remain unverified; separate token observations below do not establish them |


### Additional-client validation

Checked on 2026-09-12. These recipes use the existing service and do not extend
the validation of Agy, Claude Code or Codex to another host.

| Client | Client evidence | Tool calls / model workflow |
|---|---|---|
| Cursor CLI 2026.09.10-fd3934a | Environment header expansion and two discovery commands verified against a local HTTP server | Tool calls, IDE and model/VTAI workflows pending |
| VS Code 1.107.1 | Full application and Extension Host resolved the password input and used HTTP, including GET 405 and restart | Three local tool calls verified; model/VTAI workflow pending |
| Copilot CLI 1.0.83 | Configuration recognized and public vt-mcp 0.8.0 launched through stdio | Model called `get_domain_report` against VTAI and used its response; other tool workflows unverified |
| Devin CLI 3000.10.21 | Launched vt-mcp 0.8.0 through ACP/stdio and initialized the server | Tool discovery, calls and model/VTAI workflows pending; dedicated configuration file not exercised |
| Cascade in Windsurf / Devin Desktop | Devin Desktop 3.10.23 on Linux opened its MCP configuration editor; HTTP and token-file syntax documented | Transport, tool calls and model/VTAI workflow pending |

VS Code checks used installed commit `994fd12f8d3a5aa16f17d42c041e5809167e845a`
and the documented configuration with only its URL changed to a local server.
The native application completed initialization, GET 405, POST discovery and a
tool call on initial start, after restarting the MCP server, and after reloading
the window with a new Extension Host. A local test extension invoked the native
`vscode.lm.invokeTool` API and received each server response. These calls did not
use a model or VTAI. A synthetic password was retained across those restarts;
this does not establish the protection of credentials in a production keyring.

Cursor CLI discovery verified the documented environment-based header against a
local server. Two `list-tools` commands succeeded; the capture contains four
initialize requests, four GET 405 responses and two successful `tools/list`
responses. This does not establish recovery for every initial connection or
validate Cursor IDE, tool invocation or a model workflow.

Copilot CLI's model called `get_domain_report` once for `virustotal.com` through
the public vt-mcp 0.8.0 package. VTAI admitted the query and returned HTTP 200;
the model used the `found` result in its answer. A found report is not a safety
guarantee. This observation covers one domain lookup, not every tool or transport.

Devin CLI's ACP launch exercised the real stdio wrapper's initialization and
`prompts/list`, not `tools/list` or `tools/call`. The documented standalone
configuration and model workflow need separate validation.

The HTTP service does not offer a standalone SSE stream: an authenticated
`GET /mcp` returns **405**, while MCP requests use POST. A client may omit that
optional GET. In a client compatibility check, observe whether a GET is sent
and whether subsequent POST tool calls work; a separate helper's GET does not
prove the client handled it. Do not select legacy SSE transport for this endpoint.
[MCP transport specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports).

For a current client check, confirm discovery of eleven hosted HTTP tools (eleven with
local stdio), then ask the model to use `get_domain_report` for `virustotal.com`
and preserve the returned source, analysis date and coverage. Check the actual
tool result, not only the final answer. Repeat a report lookup after any observed
GET 405. Validate credential handling without printing its value. A successful
report lookup does not validate file submission, recovery or analysis completion.

The unverified tool/model stages above remain pending; configuration examples do not
establish a production workflow. Removing a client configuration does not revoke
the VTAI token; use the [revocation instructions](access.md#revoke-access) when
you intend to disable it across clients.

The following records retain their original dates and scope. Configuration
parsing, MCP discovery, an actual tool call and a workflow with a model are
separate observations. The generic Python SDK test is not evidence of a Claude
or Gemini model workflow.

Client checks identify the artifact and date tested. Checks for earlier
versions describe private development, not installation from this public
repository. Each public release requires its own verified CI run and checksums.

### Bearer authentication validation

**Deployment accepted: VTAI 0.8.1, 2026-09-08.** At that time, the public vt-mcp
package remained at 0.8.0. These records retain that historical scope.

On 2026-09-08, these native HTTP checks used Bearer through dedicated QA proxies,
with the same VTAI 0.8.1 image in staging and the production candidate:

| Client | Staging | Production candidate |
|---|---|---|
| Claude Code 2.1.263 | One `get_domain_report(example.com)` call and result, `found` | One call and result, `found` |
| Codex CLI 0.153.4 | One `get_domain_report(example.com)` call and result, `found` | One call and result, `found` |

Each tool result included `VirusTotal via VTAI`, its analysis/retrieval dates,
the matching report link and coverage of 89 engines. These are four observed
report calls, not validation of all tools with Bearer or a safety verdict. A
separate SDK session discovered seven tools before each check. Claude's native
initialization also listed seven; Codex's native discovery list was not exposed
in its events. Native HTTP protocol versions and internal retries were not captured.

Two earlier production-candidate attempts failed: Claude stopped before completed
discovery and native launch; Codex exited after SDK discovery without structured
native events. Their causes remain undetermined, and those failures are preserved
separately from the later sequential successes. These checks were not ordinary
public-direct connections. They establish neither Agy Bearer support nor OAuth or
hosted-connector compatibility, and do not extend the earlier submission evidence.

After rollout and removal of the temporary QA route, a separate SDK check against
the ordinary public endpoint passed 25 HTTP checks and twelve MCP calls using
`x-apikey` and Bearer separately. It discovered seven tools and called six distinct
read-only tools with each credential method; it performed no submissions. Seven
anonymous GETs also verified the landing page, three client connection links, JSON
and Markdown discovery, and llms content. Response headers confirmed the expected
backend version (0.8.1) and source.
These service checks involved no new native model sessions. The test credential
was revoked and rejected by both authentication methods.

The accepted thirty-minute observation recorded 536 requests, 535 latency samples
and zero 5xx responses, with eight functional/authentication check batteries. The
404 aggregate contained one fewer latency sample than requests; the cause
remains undetermined. The 21-sample baseline cannot support a relative p95
comparison. This does not establish complete latency coverage, equivalent
performance or organic adoption.

### Version 0.8 workflow status

| Client | Local stdio: eight tools | HTTP: seven tools |
|---|---|---|
| Antigravity CLI (`agy`) | Three-tool cycle observed in staging and production candidate | Not supported by the verified credential-reference setup in 1.1.27; use stdio |
| Claude Code | Three-tool cycle observed in staging and production candidate | Three-tool cycle observed in both environments; analysis pending in these sessions |
| Codex CLI | Three-tool cycle observed in staging and production candidate | Three-tool cycle observed in staging and production candidate |

Publication, installation and deployment of 0.8 require separate acceptance.
The new tools do not extend the guard's scope or establish that an analyzed file
is safe. The historical sections below retain their original 0.7 evidence.

### Version 0.8 submission evidence

On 2026-09-08, five native-client sessions exercised the production candidate with
**zero public traffic**. Each made exactly three MCP calls: its submission tool,
`get_submission` for the same SHA-256/account, then `get_analysis` for that registered
ID. There were no repeated submission calls in these sessions. The two innocuous
public fixtures are labelled A and B. These native results precede the separately
accepted public rollout below.

| Client | Transport | Submission tool | Selected analysis observed in the candidate session |
|---|---|---|---|
| Antigravity CLI (`agy`) 1.1.27 | Local stdio | `submit_local_file` | A receipt recovered; analysis pending |
| Claude Code 2.1.263 | Local stdio | `submit_local_file` | Same A receipt; analysis pending |
| Claude Code 2.1.263 | HTTP | `submit_file` | B receipt recovered; analysis pending |
| Codex CLI 0.153.4 | Local stdio | `submit_local_file` | Same A receipt; analysis completed |
| Codex CLI 0.153.4 | HTTP | `submit_file` | Same B receipt; analysis pending |

Both transports reached the candidate through a loopback proxy to its dedicated
route; these were not ordinary public HTTP connections. Stdio protocol versions
were 2026-07-28 for Agy, 2025-11-25 for Claude and 2025-06-18 for Codex. HTTP wire
negotiation was not captured; discovery used a separate SDK connection. Agy reported
`gemini-3.8-flash-high`; Claude reported `claude-opus-5` / `claude-opus-5[1m]` through
its native subscription. Codex requested `gpt-6-astra` / `xhigh`; its events did not
independently report the effective model. These observations do not extend the
execution guard or validate calls to every exposed tool.

Three later API reads, completed at 09:34:13 UTC, established both selected analyses
as completed without submitting again. Their IDs and hashes matched the native
receipts; A's final source, date, statistics and results also matched Codex's
completed result. A had 75 engine entries: 50 undetected, 14 unsupported, 10 timeouts
and one failure. B had 75: 38 undetected, 13 unsupported, 10 timeouts and 14 failures.
These are total entries, not 75 successful engine analyses. Later completion does
not turn a client's pending result into a completed observation; receipt recovery
does not demonstrate another upload. Zero detections do not establish safety.

Earlier **staging** evidence used five separate sessions and 15 MCP calls through a
staging proxy. Agy and Claude/Codex stdio observed staging fixture A completed;
Claude HTTP observed B pending, and Codex HTTP later observed B completed, matching
a separate API read. Each had 76 engine entries: A had 61 undetected, 14 unsupported
and one failure; B had 62 undetected and 14 unsupported. Staging fixtures are
separate from the production-candidate fixtures. Agy also read its own generated
MCP schema/result files. The [recovery guide](analysis.md#autonomous-mcp-workflow)
and historical read-only 0.7 record retain their separate scope.

#### Public rollout and direct checks

The VTAI 0.8 rollout reached 100% and was accepted after its 2026-09-08
10:30–11:00 UTC observation: 374 requests, 374 latency samples, zero 5xx responses
and eight bounded check batches. Only the first five-minute interval reached
100 requests; its p95 exceeded twice the reference. The following five intervals
had insufficient samples for that comparison, so latency recovery and performance
equivalence are not established. These counts do not measure organic adoption.

A separate direct public SDK check at 11:07:47–11:07:54 UTC passed ten HTTP checks
and seven MCP calls: four report lookups, receipt recovery, the owned completed
analysis and denial of an unowned analysis. It discovered the seven common tools
but did not submit a file. Seven separate anonymous GETs verified the public
landing, client connection pages and discovery formats. These checks used no native
model session and do not turn the candidate-proxy sessions above into public-direct
native validation. Their pending/completed results and model observations remain
unchanged.

### Historical 0.7 native-client coverage

| Client | Version | stdio | Public HTTP |
|---|---|---|---|
| Antigravity CLI (`agy`) | 1.1.27 | Five tools validated; one auxiliary read of its generated analysis output | Pending; tested header-variable references were sent literally |
| Claude Code | 2.1.263 | Five tools validated | Five tools validated |
| Codex CLI | 0.153.4 | Five tools validated with the public v0.7.0 wheel | Five tools validated |

The [five-session record](client-validation-2026-09-07.md) contains inputs, times, artifact identity, protocol observations and cleanup. All sessions read the same registered analysis; the models did not upload files.

### Earlier evidence

The following rows and session descriptions retain their recorded scope and versions. Pending checks describe those observations; current coverage for the three native clients is listed above. The ChatGPT Work row records its separate 2026-09-24 hosted validation.

| Client | Version | Transport | Configuration | Discovery / tool calls | Model workflow |
|---|---|---|---|---|---|
| Antigravity CLI (`agy`) | 1.1.27 | stdio | Public v0.7.0 wheel; token file; native login and four specific MCP permissions | Five tools discovered; four report calls once each returned found; wire version not captured | Validated report lookups; gemini-3.8-flash-high selected and reported in the client init event |
| Claude Code | 2.1.257 | stdio | Add command executed and saved configuration inspected | Health check connected using synthetic credential; tool calls pending | Pending |
| Claude Code | 2.1.263 | stdio | Public v0.7.0 wheel; per-run token-file configuration; native subscription in a PTY | Five tools discovered; four report calls once each returned found; protocol 2025-11-25 | Validated report lookups; claude-opus-5 reported in assistant messages |
| Claude Code | 2.1.257 | HTTP | Documented header expansion | Pending | Pending |
| Codex CLI | 0.153.4 | stdio | v0.2.0 CI wheel installed in a clean environment; token file configured | All four v0.2.0 tools called once against production VTAI | Validated with gpt-6-astra / xhigh; four existing reports found |
| Codex CLI | 0.153.4 | Production HTTP, `x-apikey` from environment | Direct public endpoint; no local vt-mcp process or Host override | Four calls once each; all found; wire protocol not captured | Validated with gpt-6-astra / xhigh; production source, date and coverage preserved |
| Codex CLI | 0.153.4 | Production HTTP, selected analysis | Direct public endpoint; credential supplied outside model context | One `get_analysis` call completed with the selected ID/SHA and 75 engines; no other calls | gpt-6-astra / xhigh requested; separate session, no new submission |
| Codex CLI | 0.153.4 | Local fixture HTTP | Isolated configuration exercised; local schema checked | Four synthetic calls once each; wire protocol 2025-06-18 | Earlier gpt-6-astra / xhigh fixture workflow; distinct from production |
| Gemini CLI | 0.38.1 | stdio | Add command executed and saved configuration inspected | Health check connected in a trusted temporary folder using synthetic credential; tool calls pending | Pending |
| Gemini CLI | 0.38.1 | HTTP | Installed pure resolver checked; client loading/network untested | Pending | Pending |
| Antigravity IDE | IDE 1.20.6 / CLI 1.107.0 / commit 135ccf4 | stdio | Public v0.7.0 wheel; token file and trusted system CA bundle | Five tools discovered; four report calls once each returned found; protocol 2025-06-18 | Validated report lookups; Gemini 3.6 Flash (High) shown in the UI |
| Qwen Code | Not installed; source 4248117 | stdio / proposed HTTP | Documentation/types/resolver inspected; schema limited | Pending | Pending |
| Kimi Code CLI | Not installed; source 1.50.0 / 86f1364 | stdio | Documentation/loader inspected | Pending | Pending |
| OpenCode V1 | Not installed | stdio / proposed HTTP | Public schema checked | Pending | Pending |
| OpenCode + Z.ai | Client/account untested | Proposed stdio / HTTP | Same MCP fragment; provider setup documented | Pending | Pending |
| OpenCode + DeepSeek | Client/account untested | Proposed stdio / HTTP | Same MCP fragment; provider setup documented | Pending | Pending |
| ChatGPT Work (hosted) | Web, 2026-09-24 | Production HTTP / OAuth CIMD + PKCE | Personal browser consent completed | Initial IP report and subsequent report after token expiry | Initial read and automatic renewal verified; hosted revocation, incremental authorization and writes unverified |
| Claude hosted | Account/interface untested | Organization Bearer beta documented; individual OAuth pending | Requirements reviewed | Pending | Pending |
| Python MCP SDK | 2.1.1 | stdio | Executable and token file exercised | Four tools discovered and called against synthetic HTTP backend | No model used |

Earlier Claude and Gemini configuration checks used isolated client configuration directories and a synthetic token file; the VTAI base URL pointed to loopback. They did not query production or invoke a model. A listed example or handshake alone is not a claim of full host support. The service and workflow table below records the observed scope; no external catalog publication is claimed.

Antigravity CLI 1.1.27 completed a separate production session on 2026-09-07, 18:11:13–18:11:43 UTC, using the public v0.7.0 wheel. Client events and the transparent stdio trace show exactly four report calls, no other tool calls and four `found` results. The final response preserved source, analysis dates, engine coverage of 75/90/89/89 and category counts from `data.last_analysis_stats`, with the safety limitation. The model selection was `gemini-3.8-flash-high`; the provider's internal identifier and negotiated wire version were not captured. The native environment worked without a CA override. Temporary MCP configuration and permissions were removed, and the dedicated test credential was revoked. There was no analysis call or submission; this is separate evidence from the IDE run.

Claude Code 2.1.263 completed a separate production session on 2026-09-07, 20:24:06–20:24:34 UTC, with the public v0.7.0 wheel and its native subscription login. The client reported `claude-opus-5[1m]` at initialization and `claude-opus-5` in assistant messages; usage also included an auxiliary Haiku model. A per-run configuration and four specific tool grants produced five-tool discovery, protocol `2025-11-25` and exactly four report calls, all `found`, with no other tool calls or permission denials. The final table preserved source, dates, engine coverage of 75/90/89/89 and category counts, and stated the safety limitation. It abbreviated the file hash for presentation; the complete expected hash is retained in the actual call. The temporary configuration was removed and the dedicated credential revoked after the run. No file was submitted and `get_analysis` was not called. The run used a PTY without a CA override; the cause of the earlier OAuth errors in pipe-based attempts was not established.

Earlier real-client attempts on 2026-09-07 did not establish Gemini CLI or Claude Code model workflows: Vertex authentication could not load ADC, and Claude Code returned an expired-OAuth error. The subsequent individual-account Gemini sign-in failure matches Google's retirement notice above; use `agy` for that account route. Historical configuration/discovery checks remain recorded at their tested versions. The later Claude Code stdio session above establishes the native report workflow; the earlier authentication failures are retained separately and do not establish MCP incompatibility.

The earlier remote Codex fixture used a loopback VTAI deployment with synthetic identity storage and VirusTotal responses. The client did not launch vt-mcp. All four calls completed and the server closed its resources. Its host variable was named `VTAI_TOKEN`; the example above uses `VTAI_MCP_TOKEN` with the same header mapping. This fixture evidence remains separate from the production observation below and release installation.

The production HTTP run on 2026-09-06 at 23:56 UTC used the exact public URL above and the existing VTAI identity. Codex called the empty-file hash, `https://example.com/`, `example.com` and `1.1.1.1` sequentially, once each. All four returned `found`; the final answer retained their source, actual analysis dates and engine coverage. An independent offline review of the captured events confirmed the four completed calls, no other tools and no repeated tool calls. The runner confirmed the credential was absent from its captured output. No identity was registered or file submitted. The negotiated wire version and internal transport retries were not captured; this evidence does not certify other clients, complete rollout observation or a local package installation.

A separate public HTTP session on 2026-09-07, 01:56:48–01:57:11 UTC, used Codex CLI 0.153.4 with gpt-6-astra / xhigh requested. An independent event review confirmed exactly one `get_analysis` call for the account’s existing 383-byte public-file submission: `completed`, the same registered ID and SHA-256, and 75 engines (60 `undetected`, 14 `type-unsupported`, 1 `failure`). The tool response matched the selected REST analysis except for `retrieved_at`. There was no new submission or other tool call, Host override or local MCP server. The negotiated wire version and internal HTTP retries were not captured. This establishes that selected-analysis read over public HTTP, not analysis through stdio, other models/clients, completion of rollout observation or a safety verdict.

These historical CLI and IDE sessions do not establish hosted connections or external catalog acceptance. ChatGPT's later OAuth connection, report reads and automatic renewal are recorded in the [hosted validation scope](hosted-clients.md#validation-scope); Claude hosted acceptance remains unverified. The separate Gemini CLI HTTP report check on 2 October 2026 is recorded in the [Google validation scope](google-clients.md#validation-and-discovery). Claude Code's later HTTP workflow is covered in the latest native-client record above.

The v0.2.0 Codex acceptance used the exact reviewed CI wheel, SHA256 `900daff24717b19f4a92b53d7e31429a552b6ddeccce03db63b35ee034de5ac5`. Codex queried the empty-file SHA256, `https://example.com/`, `example.com` and `1.1.1.1`, in that order, once each. All returned existing VirusTotal reports through VTAI; source, actual date and engine coverage were preserved. The client used its normal existing login and no other tools. No actor was registered and nothing was submitted. This records the historical private CI candidate’s production model workflow; it does not verify installation of a release from this public repository.

The Antigravity production run on 2026-09-07, 10:12:15–10:12:18 UTC, used the public v0.7.0 wheel (SHA256 `3e17703f2bdabbcc8db9708dee31ff7a89465365432878797385d04c419574c5`) and a dedicated test credential. A transparent stdio recorder captured the native client's five-tool discovery and exactly one call each for the empty-file hash, `https://example.com/`, `example.com` and `1.1.1.1`. All four returned `found`, with source, analysis date and coverage of 75/91/90/90 engine entries. Coverage includes incomplete outcomes and does not establish safety. The first four-call attempt returned `unavailable` because of the environment's certificate configuration; it remains recorded separately from the successful repeat after the CA adjustment. The UI showed Gemini 3.6 Flash (High); the provider's internal model identifier was not captured. The final answer preserved the report metadata and safety limitation. The temporary client configuration was removed and the test credential revoked after the run. There was no `get_analysis` call or submission. This evidence covers stdio report lookups, not Antigravity HTTP or analysis workflows.

## Optional Codex execution control

The optional local `vt-mcp guard` hook is separate from the MCP connection above. It
recognizes only `/usr/bin/python3 -I /absolute/path/script.py` under its documented
grammar, with Linux sealed-data support, a pinned policy and normal hook trust.
It does not add an MCP tool or rely on a model choosing to query MCP.

| Guard evidence | Observed scope | Limits |
|---|---|---|
| Codex CLI 0.153.4 / gpt-6-astra xhigh, earlier local guard wheel | 20 accepted cases with normal UI trust, control/observe, source replacement, disabled and modified hooks | Harmless scripts and loopback VTAI fixture; no real VirusTotal lookup or restrictive-sandbox validation |
| Same Codex host, corrected e76 CI wheel | Two real control cases: qualified copy executes; synthetic suspicious result blocks | Runner Python 3.14.7; fixed script interpreter Python 3.12.3; earlier 20 cases were not repeated |

Both used the available `danger-full-access` test profile. That observation is
not a setup recommendation or validation of a restrictive sandbox. The
[control guide](control.md#observed-host-evidence) identifies the exact earlier
artifacts and limits. Verify the installed artifact and normal hook trust; these
earlier checks do not validate every later build. Other hosts and command forms
are not covered.

## Distribution and browser acceptance

| Surface | Observed scope | Limit |
|---|---|---|
| `/connect/mcp` in Chrome 146 | Real registration, download request, diagnosis and revocation through a route pinned to the production candidate; revoked access rejected | Separate from an ordinary public-browser journey and installation of the final package |
| Staging service and connection page | Existing MCP/browser checks with test identities and real read-only reports; rollback and denial checks | No new staging run is claimed by these instructions |
| Other listed clients | Individual schema, documentation or synthetic-health levels above | Actual report calls and model workflows where marked pending |

A browser download request is not proof of saved storage or permissions. The historical
report-endpoint checks above consumed query quota. Today's access check uses
`GET /api/v3/agents/me/access` at zero query cost; neither check proves a
model called MCP. Registration can have succeeded after a connection failure;
only HTTP 204 confirms revocation.

## Service and workflow validation

| Surface | Observed scope | Limits and required verification |
|---|---|---|
| Report-only Codex stdio | Four real production queries using the exact 0.2 CI wheel | Does not establish installation of 0.7 or a model workflow using the fifth tool |
| Report-only Codex remote HTTP | Four production queries directly at the public endpoint; source, dates and coverage preserved | Negotiated wire version and internal transport retries were not captured; other clients retain their own levels |
| Selected analysis through Codex public HTTP | One separate model-assisted read of the existing public-file analysis: completed, same ID/SHA and 75 engines | No new upload, stdio-analysis validation, broader client/model support or completed rollout observation is inferred |
| Selected analysis on the VTAI staging candidate | An already-submitted analysis was recovered through CLI, REST and MCP without repeating submission | Recovery is not a new upload and does not establish a production or fifth-tool workflow with a model |
| Codex guard | Earlier local 20-case host matrix and two corrected 0.6 CI-wheel cases, as described above | Check the installed artifact and its release provenance; no broader commands, hosts or restrictive-sandbox claim |
| Public-fixture CI pilot | Eight synthetic policy cases in actual GitHub Actions, with publication-marker checks | Each release requires both live gates with the stable credential and successful evidence retention; the product itself is not scanned |
| Versioned release and source | Workflow verifies tag, same-commit main CI and exact distribution checksums | Verify the selected run, tag, retained fixture evidence and downloaded artifacts; package publication does not configure another repository’s credentials or protections |

These are separate observations. A passing synthetic workflow is not live
VirusTotal analysis, a report lookup does not upload a file, and a recovered
analysis does not establish a new submission. See [analysis](analysis.md),
[control](control.md) and [CI pilot](ci-pilot.md) for their individual contracts.
