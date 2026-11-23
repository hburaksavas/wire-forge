# WireForge

React + TypeScript interface with a Tauri 2 / Rust desktop application.

## HTTPS inspection

Settings supports HTTPS inspection for exact `host:port` targets. Stop the proxy, prepare the local CA, enter targets such as `api.company.local:443`, enable inspection, save and restart the proxy. The selected targets and enabled flag persist. Other CONNECT destinations use byte tunnels.

Configure the authorized test client to trust the public `wireforge-ca.pem` certificate shown in Settings. The UI exposes its PEM and SHA-256 fingerprint. Trust-store installation is a user action. Tests use isolated trust stores and install no system certificates.

The CA certificate and encrypted signing key are stored in `inspection-ca.json` in the per-user application data directory. Windows DPAPI protects the key under the current user profile. Existing plaintext key files are validated and atomically migrated while preserving the CA identity. The public PEM remains shareable. Automatic CA rotation remains pending.

Protected CA storage currently requires Windows. A copied CA file may be unreadable under another Windows account or a different user profile. DPAPI errors and invalid protected data preserve the stored file and prevent that CA from loading. Temporary plaintext buffers are cleared after use. This protects the stored key at rest; software running as the same Windows user can access DPAPI-protected data. The CA lasts one year and leaf certificates last seven days.

Inspected requests use the existing capture and mock pipeline. Forwarded HTTPS validates the origin hostname and certificate against system trust roots, either directly or through authenticated upstream CONNECT. Invalid origin certificates produce gateway errors. Decrypted requests cannot switch to another CONNECT authority.

This milestone supports HTTP/1.1 over TLS. Certificate-pinned clients, mutual TLS, HTTP/2 inspection and HTTPS replay remain unsupported. The proxy starts manually and HTTPS inspection defaults to disabled.

TLS tests cover persisted CA identity, HTTPS mocks/capture, authenticated upstream CONNECT, origin certificate rejection, client CA trust requirements, authority isolation and pass-through for unselected targets.

## Development

Windows requires Rust with the MSVC toolchain, Microsoft C++ Build Tools with the Desktop development with C++ workload, Windows SDK, Node.js and WebView2 Runtime.

```powershell
npm ci
npm run tauri dev
```

Use `npm run dev` for the React interface preview. Preview rule editing stays in the page. Desktop execution is required for network operations.

## Proxy and mocking

The proxy binds to 127.0.0.1:8080. Start it using the desktop toolbar.

- HTTP absolute-form requests are forwarded unless a mock matches.
- Mock rules match the HTTP method and exact path, including query parameters. They return UTF-8 text with a configured content type and status. JSON content types are validated. Rules are saved in the application data directory and restored at startup.
- HTTPS CONNECT uses a TCP tunnel by default. Selected targets support HTTPS inspection, capture and mock responses.
- HTTP response bodies stream to the client with backpressure. Request and response body previews retain up to 16 KiB per entry, with header previews limited to 16 KiB per direction.
- Request bodies are buffered up to 8 MiB with a 30 second timeout.
- A maximum of 256 connections, including tunnels, are admitted. Additional connections are closed.
- HTTP connections have a five minute lifetime, tunnels a one hour lifetime. Stopping the proxy cancels active connections.
- The history retains the most recent 1,000 entries. Timing measures time to response headers or mock creation.
- HTTP Upgrade / WebSocket inspection remains pending.

Create a GET /api/health rule, then test:

```powershell
Invoke-WebRequest http://127.0.0.1:8080/api/health
curl.exe --proxy http://127.0.0.1:8080 http://example.com/
curl.exe --proxy http://127.0.0.1:8080 https://example.com/
```

## Upstream corporate proxy

In Settings, enter the HTTP proxy host and port, enable upstream routing, and save the connection while the local proxy is stopped and the application window is closed. HTTP absolute-form requests and HTTPS CONNECT tunnels use the configured proxy. Matching HTTP mocks are handled locally. Upstream failure returns a gateway error and never triggers direct fallback.

Anonymous and Basic proxy authentication are supported. Client-supplied Proxy-Authorization is stripped. Configured credentials are sent only to the upstream proxy and are kept in memory. Re-enter the password after restarting WireForge before starting an authenticated route. Basic authentication uses Base64 over the HTTP proxy connection, so network policy must allow this authentication method. Settings snapshots exclude the password. Changing the upstream host, port or username requires entering the password again.

An upstream HTTP 407 produces an actionable gateway error. NTLM, Kerberos/Negotiate, PAC, SOCKS and TLS connections to the upstream proxy remain pending. HTTPS destinations are supported through CONNECT over the HTTP upstream connection. The upstream HTTP leg currently opens one connection per request. Performance testing and upstream connection pooling remain pending.

## Checks

The desktop interface uses a compact navigation rail, traffic type filters, method/status badges, a resizable request inspector and a JSON viewer with line numbers. Panel resizing supports dragging and the left/right arrow keys. In development, `http://127.0.0.1:5173/?preview` loads explicitly labeled sample traffic for visual review; these fixtures are excluded from production builds. The normal desktop starts with real traffic only. Icons, typography fallbacks and styling are local, without external font or UI asset requests.

```powershell
npm run build
cargo test --manifest-path src-tauri/Cargo.toml --bin wireforge
```

The Rust tests use local ephemeral ports to check mock matching, POST forwarding, hop-by-hop header removal, CONNECT byte transfer, listener shutdown/restart, chained HTTP/CONNECT, Basic and anonymous authentication, credential handling, upstream failure without direct fallback, and mock precedence.

Validation completed on the development machine includes frontend builds, 54 Windows Rust tests, the separately run native WebView2 scenario and desktop builds. The initial HTTP mock milestone was also verified through the desktop UI. TLS functionality and DPAPI storage are verified through local integration tests, including legacy migration and corrupted-key rejection. Load/performance testing and validation inside the corporate environment remain pending.

Rust stable was installed using the official rustup installer without modifying the system PATH. If Cargo is not on your PATH, use `%USERPROFILE%\.cargo\bin\cargo.exe` or add that directory to your current development shell PATH.

## Persistent workspace

The application stores mock rules and non-secret upstream connection settings in `workspace.json` inside Tauri's application data directory. Settings displays the full path. Proxy startup is manual and traffic history remains in memory.

Writes use a synchronized temporary file in the same directory followed by an atomic replacement. Runtime settings are changed after the file save succeeds. A workspace lock prevents concurrent application instances from overwriting the same file. Disk I/O runs outside the network processing threads.

The stored connection contains the host, port, enabled flag, authentication mode and username. The upstream password is excluded. Mock response bodies are stored as entered. After restarting, an authenticated upstream requires entering and saving its password before the proxy starts.

If workspace loading fails or its version is unsupported, the application shows a warning and preserves the original file. Starting the proxy and saving changes are disabled until that file is repaired or moved and the app is restarted. This prevents an unreadable corporate route from silently becoming a direct route.

Persistence checks cover replacement and restart loading, omitted optional fields, malformed and future-version files, secret omission and exclusive workspace locking. The desktop build passed. Desktop interaction for this milestone could not be verified because the automation surface reported the window as minimized.

## Traffic inspection

Traffic details include Request, Response and Headers tabs. Request bodies and completed response bodies have a 16 KiB preview limit. A large response still streams in full to the client. The response byte count tracks the transmitted body size. Headers retain at most 16 KiB per direction and omit Proxy-Authorization. Other request and response headers may contain credentials or cookies and are visible in the local inspector. Traffic history is held in memory.

Forwarded responses appear while streaming. Completion, failure or client cancellation updates the same entry using a monotonic revision cursor. Chunk boundaries do not affect the preview. gzip, zlib/raw deflate and Brotli text bodies are decoded for bounded previews. Binary, invalid and unsupported encodings display an availability message. Binary downloads remain pending.

Create mock from response prepares an editable mock draft from a complete, untruncated JSON response, including its method, path/query, body and status. Add rule saves it to the workspace. Mock responses use the configured content type. Additional response header replication is pending.

Tests additionally verify request capture, complete body capture, bounded large previews with full downstream delivery, chunked response revisions, incomplete bodies, header limits and encoded/binary preview handling.

## Replay and history controls

Use Replay on a captured HTTP request, or compose a new request in Replay. Review the method, absolute HTTP(S) URL, headers (JSON name/value pairs) and body, then press Send. Choose Text for UTF-8 input, Base64 for encoded binary bytes, or Load file to use a file as the raw request body. Replay goes through the running local proxy, mock rules and upstream configuration. Response data streams through the proxy and is discarded by the replay client after capture. The replay timeout is 30 seconds, including connection, TLS and response draining. Request bodies are limited to 8 MiB of decoded bytes. Base64 must have valid padding and no whitespace; invalid encodings and oversized data are rejected before connection. Older command payloads without bodyEncoding retain UTF-8 text behavior.

Load file checks the file size before reading it and holds its Base64 data outside the text editor to avoid rendering multi-megabyte text. The file card shows its name and exact size; Remove returns to manual input. Content-Type is inferred from the file, with application/octet-stream as the fallback, only when that header is absent. Existing headers remain editable. Content-Length and transfer framing are rebuilt for the actual decoded bytes. File loading does not send a request, upload a file elsewhere or wrap it in multipart/form-data. Files stay in memory and are not saved to the workspace.

Binary and truncated captured bodies are not retained in full. Replay can prepare their method, URL and captured headers, but Send remains disabled until the original body is supplied through a file or manual input. Complete decoded text drafts remove Content-Encoding. Drafts with missing bodies preserve it so original encoded wire bytes can be loaded; adjust the header if supplying decoded data instead. Requests with incomplete captured headers require manual composition.

For HTTPS replay, prepare the WireForge CA and enable HTTPS inspection for the exact destination host:port or All HTTPS hosts before starting the proxy. Replay uses CONNECT through the local proxy, then verifies the inspection certificate using only the current WireForge CA in memory. This does not install or trust that CA in Windows or another browser. The proxy continues to validate the real backend certificate against its configured trusted roots and uses the configured corporate CONNECT route. Both the CONNECT and inspected HTTP request appear in Traffic. Missing inspection selection or CA is rejected before connecting; replay does not silently switch to an uninspected tunnel. HTTPS input without an explicit port uses 443. Embedded credentials, fragments and invalid ports are rejected.

Replay checks cover HTTP/HTTPS mock capture, exact binary delivery including NULL/non-UTF-8 bytes over HTTP and authenticated HTTPS CONNECT, rebuilt body framing, strict Base64 validation, the decoded 8 MiB boundary, legacy text input, missing inspection/CA and rejection of a certificate with the wrong server name. Existing TLS tests also cover upstream certificate rejection and proxy authentication failure.

Replay can modify data on the destination service, including through POST, PUT, PATCH and DELETE. Drafting a replay does not send it. Request bodies with unavailable or truncated previews must be supplied in full before sending; a retained prefix is not sent as the original body.

Clear traffic removes the in-memory history. Active response completions update only retained entries, and sequence numbers continue monotonically. New requests can appear after clearing while the proxy remains running.

Decompression runs outside the network processing threads. Encoded input and decoded output previews are bounded to 16 KiB, with at most three content-encoding layers. A preview may be unavailable when the retained compressed prefix is incomplete. Original request and response bytes and Content-Encoding headers continue to pass through unchanged. Response byte counts measure encoded bytes.

## Full HTTP capture mode

HTTPS inspection settings include All HTTPS hosts. With inspection enabled and the CA trusted by the client, CONNECT traffic is inspected without maintaining a per-host list. Exact-target mode remains available. These settings persist with the workspace.

Valid HTTP requests appear immediately with a pending status and update in place when response headers arrive. Local validation errors, rejected upgrades, upstream failures and cancellation before response headers are recorded. Request and response headers and bounded body previews are available in the inspector. JSON and other UTF-8 text responses can be used as mock drafts, with the response content type preserved.

Coverage requires the client to route traffic through WireForge. The application does not automatically change system proxy settings or install CA trust. HTTP/2 inspection, WebSocket forwarding, binary mock bodies and certificate-pinning compatibility remain pending. The table retains the latest 1,000 entries and body previews remain limited to 16 KiB. This is not packet capture of all system network traffic.

## Embedded application window (Windows)

In Traffic, enter your frontend URL and press **Open app**. WireForge opens a separate WebView2 window and records its HTTP(S) requests in the same traffic list. Existing enabled mock rules apply by method and exact path/query. Cross-origin mocks also handle matching CORS preflight requests. Backend addresses remain unchanged. The proxy listener does not need to be started and a WireForge CA is not needed for this mode. Normal TLS certificate validation remains enabled.

Capture uses the in-process WebView2 DevTools Protocol with bounded browser buffers, without an external debugging port or injected fetch overrides. Failed mock delivery fails the request rather than forwarding it to the backend. The application window has an isolated persistent browser profile and cannot invoke WireForge management commands. Use **Reload** to reload the page. Close it with **Close** or the window close button before opening another address. The controls track native window state, including closure from the title bar.

When upstream routing is enabled, the application window uses the HTTP proxy configured in Settings, without starting the local proxy listener. Basic credentials are supplied only to Basic proxy challenges from that configured host and port, with one attempt per recent request. Origin-server authentication uses normal browser handling and never receives the configured proxy credentials. Repeated or unrelated proxy challenges are cancelled. The browser receives a single proxy route without a direct fallback route. WebView2's standard loopback bypass remains in place so localhost frontends stay local. With upstream routing disabled, Windows/browser proxy settings apply. Route changes require closing the application window. Different configured proxy routes use separate profile directories to avoid incompatible WebView2 environment settings.

This mode captures the embedded page's network activity, not other applications. Browser cookies and logins are independent of Chrome/Edge profiles. Popup windows are blocked. Streaming HTTP body previews are not implemented. Browser cache and service workers can affect which requests reach the network. Response bodies are read after completion when available, capped by a 1 MiB per-resource browser buffer, with 16 KiB text previews. The displayed transfer size comes from the browser and may be zero for cached or mocked responses. Corporate WebView2 policy can restrict this feature.

### WebSocket messages and workers

WebSocket connections appear as **WS** rows. Select one to inspect **Messages** or **Headers**. Messages show direction, elapsed time, original byte count and a bounded payload. Text is displayed as UTF-8; binary and control payloads use Base64. Connection state tracks connecting, open, closed and failed. Each connection retains at most 64 messages and 16 KiB of message previews in total, with at most 4 KiB per message. Older messages are dropped and counted. Clear traffic also discards subsequent updates for removed connections. WebSocket observation is specific to the embedded WebView and does not add WebSocket forwarding to the Rust proxy listener.

Use a message's **Use** action to prepare an editable payload. **Send** sends text or Base64-decoded binary data through the selected existing connection and its active mock rules. **Inject** delivers a local incoming message to the application. Each action requires an open, instrumented connection and accepts at most 64 KiB of decoded payload. Truncated previews and non-data control frames cannot be copied with Use. Closed, cleared, unavailable and stale connection IDs are rejected. Replay uses the current browser connection, cookies, subprotocol and proxy route; it does not open a new connection or recreate an old handshake.

**Mock** on a complete text message prepares an exact-match rule. For outgoing text, **Local reply** suppresses that message before network transmission and injects the configured response. For incoming text, **Replace incoming** substitutes the configured response before the application handles it. Matches include the full canonical WebSocket URL and query, direction and exact text. Up to 100 rules persist in the workspace and can be enabled or deleted in Messages or Mock rules. Saving updates active controllers and future navigations. Rule updates are serialized with application open/reload operations. If controllers cannot be updated, the rules remain saved and the application window closes with a message to reopen it, avoiding continued operation with an uncertain rule set.

History labels **Wire**, **Mock** and **Blocked** distinguish actual network frames, locally delivered messages and suppressed outgoing messages. Replacing an incoming message retains the original Wire capture and adds its Mock replacement. Binary Send/Inject are supported; automatic rules match text only. The initial connection and handshake still reach the server, so message mocking requires a live WebSocket endpoint. Synthetic incoming events have `isTrusted === false` and applications that require trusted events may ignore them. Clearing traffic does not disable saved mock rules.

Control uses a WebSocket constructor wrapper inside the application page and instrumented worker contexts, installed through [CDP document scripts](https://chromedevtools.github.io/devtools-protocol/tot/Page/#method-addScriptToEvaluateOnNewDocument) and [runtime bindings](https://chromedevtools.github.io/devtools-protocol/tot/Runtime/#method-addBinding). Network observation remains native. Connections created before the wrapper is installed remain observable but may have disabled controls; open a new connection to use Send/Inject. Cached original constructors, native prototype calls or application overrides can bypass message mocking. Very early worker startup, especially service workers, may precede controller installation. Payload evaluation uses a unique execution context ID so a stale action cannot target a recycled numeric context after navigation.

Dedicated workers, shared workers and service workers have separate CDP capture sessions and use the same HTTP mock rules. Out-of-process frames are also attached. Worker API requests display `worker` as the source, or `mock` for a mocked response. Shared/service-worker mocks use WebView2's native request source filters because these targets do not support the CDP Fetch domain. Existing traffic from before attachment is not recovered, and very early worker bootstrap headers or bodies may be unavailable. Capturing starts with the application window; it does not attach to Chrome/Edge or other applications' workers.

Capture is limited to 64 attached targets, 1,000 active root requests and 128 active requests per child target. Each child uses a 2 MiB browser response buffer. Exceeding a request limit expires the oldest active capture while the application request continues. A target-capacity or instrumentation error appears as a CAPTURE row. The latest 1,000 traffic rows remain the overall history limit. A current WebView2 runtime with native shared/service-worker request filtering is required. The session routing follows the [WebView2 CDP session API](https://learn.microsoft.com/en-us/microsoft-edge/webview2/reference/win32/icorewebview2_11) and [CDP target attachment model](https://chromedevtools.github.io/devtools-protocol/tot/Target/).

Native validation opens real WebView2 windows against local HTTP/WebSocket servers and an authenticated test proxy. It verifies cross-origin POST mock/preflight delivery, worker API capture and mocks, WebSocket observation, outgoing local reply without backend delivery, incoming replacement, text/binary Send and Inject, live rule disabling, rules after reload, rejection of invalid/oversized payloads and stale connections, redirects, 407 Basic authentication and absence of backend/proxy hits for mocked requests:

```powershell
cargo test --manifest-path src-tauri/Cargo.toml --bin wireforge native_webview_capture -- --ignored --nocapture --test-threads=1
```

## License

MIT, see [LICENSE](LICENSE).
