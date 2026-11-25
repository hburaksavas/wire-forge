import {useEffect, useRef, useState, type CSSProperties} from 'react';
import {createRoot} from 'react-dom/client';
import {invoke, isTauri} from '@tauri-apps/api/core';
import './style.css';
import {Icon, CodeView, EmptyState, addressParts} from './ui';
import {createPreviewEntries} from './preview';

type MatchType = 'exact' | 'wildcard' | 'regex';
type HeaderPair = {name: string; value: string};
type Rule = {id: string; method: string; path: string; body: string; contentType: string; status: number; enabled: boolean; matchType?: MatchType; requestHeaders?: HeaderPair[]; responseHeaders?: HeaderPair[]};
const matchLabels: Record<MatchType, string> = {exact: 'Exact', wildcard: 'Wildcard', regex: 'Regex'};
const pathHints: Record<MatchType, string> = {
  exact: 'Exact path and query, e.g. /api/health?ready=1',
  wildcard: '* matches any characters, including / and ?, e.g. /api/users/*',
  regex: 'Regular expression matched against the full path and query, e.g. /users/\\d+',
};

// One "Name: value" pair per line. An empty value is allowed for request conditions.
function parseHeaderLines(source: string, label: string): HeaderPair[] {
  return source.split('\n').map(line => line.trim()).filter(Boolean).map(line => {
    const separator = line.indexOf(':');
    const name = (separator < 0 ? line : line.slice(0, separator)).trim();
    if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name)) throw new Error(`${label}: "${line}" needs a valid header name.`);
    return {name, value: separator < 0 ? '' : line.slice(separator + 1).trim()};
  });
}
type SocketRule = {id: string; url: string; direction: string; matchText: string; responseText: string; enabled: boolean};
type Entry = {
  messages: {direction: string; opcode: number; elapsedMs: number; payload: string; bytes: number; truncated: boolean; kind: string}[];
  socketControl: boolean;
  messagesDropped: number;
  id: number; revision: number; method: string; url: string; status: number; durationMs: number;
  responseBody: string; requestBody: string; source: string; bodyState: string;
  requestHeaders: [string, string][]; responseHeaders: [string, string][];
  requestTruncated: boolean; responseTruncated: boolean; responseBytes: number;
  requestAvailable: boolean; responseAvailable: boolean;
};
type Upstream = {enabled: boolean; host: string; port: number; username: string; basicAuth: boolean; passwordConfigured: boolean};
type TlsSettings = {enabled: boolean; allHosts: boolean; targets: string[]};
type CaInfo = {certificatePath: string; certificatePem: string; fingerprint: string; keyProtection: string};
const desktop = isTauri();
const previewMode = import.meta.env.DEV && !desktop && new URLSearchParams(window.location.search).has('preview');
const replayMethods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'];

function HeaderList({headers}: {headers: [string, string][]}) {
  return headers.length ? <dl className="header-list">{headers.map(([name, value], index) => <div key={index}><dt>{name}</dt><dd>{value}</dd></div>)}</dl> : <span className="muted">None</span>;
}

function replayHeaderPairs(source: string): [string, string][] {
  const headers: unknown = JSON.parse(source);
  if (!Array.isArray(headers) || !headers.every(row => Array.isArray(row) && row.length === 2 && row.every(value => typeof value === 'string'))) {
    throw new Error('Headers must be a JSON array of [name, value] pairs.');
  }
  return headers as [string, string][];
}

function App() {
  const [tab, setTab] = useState('Traffic');
  const [error, setError] = useState('');
  const [running, setRunning] = useState(false);
  const [busy, setBusy] = useState(false);
  const [rules, setRules] = useState<Rule[]>([]);
  const [entries, setEntries] = useState<Entry[]>(() => previewMode ? createPreviewEntries() : []);
  const [selectedId, setSelectedId] = useState<number | undefined>(previewMode ? 3 : undefined);
  const [detailTab, setDetailTab] = useState('Response');
  const [filter, setFilter] = useState('');
  const [trafficType, setTrafficType] = useState('All');
  const [trafficSplit, setTrafficSplit] = useState(55);
  const [method, setMethod] = useState('GET');
  const [path, setPath] = useState('/api/health');
  const [body, setBody] = useState('{\n  "status": "ok"\n}');
  const [status, setStatus] = useState(200);
  const [contentType, setContentType] = useState('application/json');
  const [matchType, setMatchType] = useState<MatchType>('exact');
  const [conditionText, setConditionText] = useState('');
  const [responseHeaderText, setResponseHeaderText] = useState('');
  const [upstream, setUpstream] = useState<Upstream>({enabled: false, host: '', port: 3128, username: '', basicAuth: false, passwordConfigured: false});
  const [password, setPassword] = useState('');
  const [settingsMessage, setSettingsMessage] = useState('');
  const [workspacePath, setWorkspacePath] = useState('');
  const [startupWarning, setStartupWarning] = useState('');
  const [ready, setReady] = useState(!desktop);
  const [replayMethod, setReplayMethod] = useState('GET');
  const [replayUrl, setReplayUrl] = useState('');
  const [replayHeaders, setReplayHeaders] = useState('[]');
  const [replayBody, setReplayBody] = useState('');
  const [replayBodyEncoding, setReplayBodyEncoding] = useState<'text' | 'base64'>('text');
  const [replayNeedsOriginal, setReplayNeedsOriginal] = useState(false);
  const [replayFile, setReplayFile] = useState<{name: string; size: number}>();
  const [replayLoading, setReplayLoading] = useState(false);
  const replayFileBody = useRef<string | undefined>(undefined);
  const replayFileInput = useRef<HTMLInputElement>(null);
  const replayFileReader = useRef<FileReader | undefined>(undefined);
  const replayLoadVersion = useRef(0);
  const [replayMessage, setReplayMessage] = useState('');
  const trafficGeneration = useRef(0);
  const [tlsEnabled, setTlsEnabled] = useState(false);
  const [tlsTargets, setTlsTargets] = useState('');
  const [allHosts, setAllHosts] = useState(false);
  const [ca, setCa] = useState<CaInfo>();
  const [tlsWarning, setTlsWarning] = useState('');
  const [tlsMessage, setTlsMessage] = useState('');
  const [applicationUrl, setApplicationUrl] = useState('http://localhost:3000');
  const [openingApplication, setOpeningApplication] = useState(false);
  const [applicationOpen, setApplicationOpen] = useState(false);
  const [socketRules, setSocketRules] = useState<SocketRule[]>([]);
  const [socketPayload, setSocketPayload] = useState('');
  const [socketBinary, setSocketBinary] = useState(false);
  const [socketBusy, setSocketBusy] = useState(false);
  const [socketDraft, setSocketDraft] = useState<{direction: string; matchText: string}>();

  useEffect(() => {setSocketPayload(''); setSocketBinary(false); setSocketDraft(undefined);}, [selectedId]);

  async function updateSocketRules(next: SocketRule[]) {
    setSocketBusy(true); setError('');
    try {
      const saved = await invoke<{rules: SocketRule[]; warning: string | null}>('save_socket_rules', {rules: next});
      setSocketRules(saved.rules);
      if (saved.warning) setError(saved.warning);
      setSocketDraft(undefined);
    } catch (error) {setError(String(error));}
    finally {setSocketBusy(false);}
  }

  async function socketAction(action: 'send' | 'inject', id: number) {
    setSocketBusy(true); setError('');
    try {await invoke('socket_action', {id, action, payload: socketPayload, binary: socketBinary});}
    catch (error) {setError(String(error));}
    finally {setSocketBusy(false);}
  }

  function renderSocketRules(items: SocketRule[]) {
    return items.map(rule => <article className="socket-rule" key={rule.id}>
      <div className="section-heading"><strong className={!rule.enabled ? 'muted' : ''}>{rule.direction === 'out' ? 'Local reply' : 'Replace incoming'}</strong>
        <button disabled={socketBusy || !ready || !!startupWarning} onClick={() => void updateSocketRules(socketRules.map(item => item.id === rule.id ? {...item, enabled: !item.enabled} : item))}>{rule.enabled ? 'Disable' : 'Enable'}</button>
        <button disabled={socketBusy || !ready || !!startupWarning} onClick={() => void updateSocketRules(socketRules.filter(item => item.id !== rule.id))}>Delete</button>
      </div>
      <details><summary title={rule.url}>{rule.url}</summary><pre>{rule.matchText}</pre><h3>Response</h3><pre>{rule.responseText}</pre></details>
    </article>);
  }

  async function applicationAction(action: 'open' | 'reload' | 'close' = 'open') {
    setOpeningApplication(true);
    setError('');
    try {
      await invoke(`${action}_application`, action === 'open' ? {url: applicationUrl} : {});
      setApplicationOpen(action !== 'close');
    }
    catch (error) { setError(String(error)); }
    finally { setOpeningApplication(false); }
  }

  useEffect(() => {
    if (!desktop) return;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout>;
    let afterId: number | null = null;
    async function refresh() {
      const generation = trafficGeneration.current;
      try {
        const snapshot = await invoke<{running: boolean; applicationOpen: boolean; socketRules: SocketRule[] | null; rules: Rule[] | null; upstream: Upstream | null; workspacePath: string | null; startupWarning: string | null; tls: TlsSettings | null; ca: CaInfo | null; tlsWarning: string | null; traffic: Entry[]}>('get_snapshot', {afterId});
        if (cancelled) return;
        setRunning(snapshot.running);
        setApplicationOpen(snapshot.applicationOpen);
        if (snapshot.socketRules) setSocketRules(snapshot.socketRules);
        if (snapshot.workspacePath) setWorkspacePath(snapshot.workspacePath);
        if (snapshot.startupWarning) setStartupWarning(snapshot.startupWarning);
        if (snapshot.tls) { setTlsEnabled(snapshot.tls.enabled); setAllHosts(snapshot.tls.allHosts); setTlsTargets(snapshot.tls.targets.join('\n')); }
        if (snapshot.ca) setCa(snapshot.ca);
        if (snapshot.tlsWarning) setTlsWarning(snapshot.tlsWarning);
        setReady(true);
        if (snapshot.upstream) setUpstream({...snapshot.upstream, port: snapshot.upstream.port || 3128});
        if (snapshot.rules) setRules(snapshot.rules);
        if (generation === trafficGeneration.current && snapshot.traffic.length) {
          afterId = Math.max(afterId ?? 0, ...snapshot.traffic.map(entry => entry.revision));
          setEntries(items => {
            const merged = new Map(items.map(entry => [entry.id, entry]));
            snapshot.traffic.forEach(entry => merged.set(entry.id, entry));
            return [...merged.values()].sort((left, right) => left.id - right.id).slice(-1000);
          });
        } else if (afterId === null) { afterId = 0; }
      } catch (e) { if (!cancelled) setError(String(e)); }
      if (!cancelled) timer = setTimeout(refresh, 250);
    }
    void refresh();
    return () => { cancelled = true; clearTimeout(timer); };
  }, []);

  async function toggleServer() {
    setBusy(true);
    setError('');
    try {
      await invoke(running ? 'stop_proxy' : 'start_proxy');
      setRunning(!running);
    } catch (e) { setError(String(e)); }
    finally { setBusy(false); }
  }

  async function updateRules(next: Rule[]) {
    setBusy(true);
    try {
      if (desktop) await invoke('save_rules', {rules: next});
      setRules(next);
      setError('');
    } catch (e) { setError(String(e)); }
    finally { setBusy(false); }
  }

  async function saveUpstream() {
    setBusy(true);
    setSettingsMessage('');
    setError('');
    try {
      if (upstream.enabled && (!upstream.host.trim() || !Number.isInteger(upstream.port) || upstream.port < 1 || upstream.port > 65535)) {
        throw new Error('Enter the upstream proxy host and a port from 1 to 65535.');
      }
      const saved = await invoke<Upstream>('save_upstream', {config: {
        enabled: upstream.enabled, host: upstream.host, port: upstream.port,
        username: upstream.username, basicAuth: upstream.basicAuth,
        password: password || (upstream.passwordConfigured ? null : ''),
      }});
      setUpstream(saved);
      setPassword('');
      setSettingsMessage(saved.enabled ? 'Upstream saved.' : 'Direct route saved.');
    } catch (e) { setError(String(e)); }
    finally { setBusy(false); }
  }

  async function prepareCa() {
    setBusy(true);
    setError('');
    setTlsMessage('');
    try {
      const info = await invoke<CaInfo>('prepare_ca');
      setCa(info);
      setTlsWarning('');
      setTlsMessage('CA ready. Client trust required.');
    } catch (e) { setError(String(e)); }
    finally { setBusy(false); }
  }

  async function saveTls() {
    setBusy(true);
    setError('');
    setTlsMessage('');
    try {
      const targets = [...new Set(tlsTargets.split('\n').map(value => value.trim()).filter(Boolean))];
      const saved = await invoke<TlsSettings>('save_tls', {config: {enabled: tlsEnabled, allHosts, targets}});
      setTlsEnabled(saved.enabled);
      setAllHosts(saved.allHosts);
      setTlsTargets(saved.targets.join('\n'));
      setTlsMessage(saved.enabled ? 'Inspection saved.' : 'Inspection disabled.');
    } catch (e) { setError(String(e)); }
    finally { setBusy(false); }
  }

  async function copyCa() {
    if (!ca) return;
    try {
      await navigator.clipboard.writeText(ca.certificatePem);
      setTlsMessage('Certificate copied.');
    } catch { setError('Clipboard is unavailable. Use the public certificate file shown below.'); }
  }

  function addRule() {
    try {
      if (contentType.toLowerCase().includes('json')) JSON.parse(body);
      if (matchType === 'regex') {
        if (!path) throw new Error('Enter a regular expression.');
        try { new RegExp(path); } catch { throw new Error('Enter a valid regular expression.'); }
      } else if (!path.startsWith('/')) throw new Error('The path must start with /.');
      if (!Number.isInteger(status) || status < 200 || status > 599) throw new Error('Enter a status from 200 to 599.');
      const requestHeaders = parseHeaderLines(conditionText, 'Request condition');
      const responseHeaders = parseHeaderLines(responseHeaderText, 'Response header');
      const conditionKey = JSON.stringify(requestHeaders);
      if (rules.some(rule => rule.method === method && rule.path === path && (rule.matchType ?? 'exact') === matchType && JSON.stringify(rule.requestHeaders ?? []) === conditionKey)) {
        throw new Error('A rule with this method, path and conditions already exists.');
      }
      void updateRules([...rules, {id: crypto.randomUUID(), method, path, body, contentType, status, enabled: true, matchType, requestHeaders, responseHeaders}]);
    } catch (e) { setError(e instanceof SyntaxError ? 'Enter a valid JSON response.' : e instanceof Error ? e.message : String(e)); }
  }

  async function clearTraffic() {
    setBusy(true);
    trafficGeneration.current += 1;
    try {
      if (desktop) await invoke('clear_traffic');
      trafficGeneration.current += 1;
      setEntries([]);
      setSelectedId(undefined);
      setError('');
    } catch (e) { setError(String(e)); }
    finally { setBusy(false); }
  }

  function draftReplay(entry: Entry) {
    if (!replayMethods.includes(entry.method) || entry.requestHeaders.some(([name]) => name === 'preview')) {
      setError('Replay requires captured headers. Compose a request in Replay instead.');
      return;
    }
    replayLoadVersion.current += 1;
    replayFileReader.current?.abort();
    replayFileReader.current = undefined;
    setReplayLoading(false);
    replayFileBody.current = undefined;
    setReplayFile(undefined);
    const completeText = entry.requestAvailable && !entry.requestTruncated;
    const host = entry.requestHeaders.find(([name]) => name.toLowerCase() === 'host')?.[1] || '127.0.0.1:8080';
    setReplayUrl(new URL(entry.url, `http://${host}`).href);
    setReplayMethod(entry.method);
    setReplayBody(completeText ? entry.requestBody : '');
    setReplayBodyEncoding(completeText ? 'text' : 'base64');
    setReplayNeedsOriginal(!completeText);
    const excluded = ['host', 'content-length', 'transfer-encoding', 'connection', 'proxy-connection', 'proxy-authorization', 'expect', ...(completeText ? ['content-encoding'] : [])];
    setReplayHeaders(JSON.stringify(entry.requestHeaders.filter(([name]) => !excluded.includes(name.toLowerCase())), null, 2));
    setReplayMessage('');
    setError('');
    setTab('Replay');
  }

  async function loadReplayFile(file: File) {
    const version = ++replayLoadVersion.current;
    setReplayLoading(true); setError('');
    try {
      if (file.size > 8 * 1024 * 1024) throw new Error('Replay body exceeds 8 MiB.');
      const headers = replayHeaderPairs(replayHeaders);
      const encoded = await new Promise<string>((resolve, reject) => {
        const reader = new FileReader();
        replayFileReader.current = reader;
        reader.onerror = () => reject(new Error('Could not read the selected file.'));
        reader.onabort = () => reject(new Error('File loading cancelled.'));
        reader.onload = () => {
          if (typeof reader.result !== 'string' || !reader.result.includes(',')) { reject(new Error('Could not encode the selected file.')); return; }
          resolve(reader.result.slice(reader.result.indexOf(',') + 1));
        };
        reader.readAsDataURL(file);
      });
      if (version !== replayLoadVersion.current) return;
      replayFileBody.current = encoded;
      setReplayFile({name: file.name, size: file.size});
      setReplayBody(''); setReplayBodyEncoding('base64'); setReplayMessage('');
      if (!headers.some(([name]) => name.toLowerCase() === 'content-type')) {
        setReplayHeaders(JSON.stringify([...headers, ['Content-Type', file.type || 'application/octet-stream']], null, 2));
      }
    } catch (error) {
      if (version === replayLoadVersion.current) setError(error instanceof SyntaxError ? 'Enter headers as a valid JSON array.' : String(error));
    } finally {
      if (version === replayLoadVersion.current) { setReplayLoading(false); replayFileReader.current = undefined; }
    }
  }

  async function sendReplay() {
    setBusy(true);
    setError('');
    setReplayMessage('');
    try {
      if (replayLoading || (replayNeedsOriginal && !replayFile && !replayBody.length)) throw new Error('Provide the original request body before replaying.');
      const headers = replayHeaderPairs(replayHeaders);
      const status = await invoke<number>('replay_request', {input: {method: replayMethod, url: replayUrl, headers, body: replayFileBody.current ?? replayBody, bodyEncoding: replayBodyEncoding}});
      setReplayMessage(`Response ${status}`);
    } catch (e) { setError(e instanceof SyntaxError ? 'Enter headers as a valid JSON array.' : String(e)); }
    finally { setBusy(false); }
  }

  function draftMock(entry: Entry) {
    try {
      if (entry.method === 'CONNECT' || entry.bodyState !== 'complete' || entry.responseTruncated || !entry.responseAvailable) {
        throw new Error('A complete text response is required to create a mock.');
      }
      const type = entry.responseHeaders.find(([name]) => name.toLowerCase() === 'content-type')?.[1] || 'text/plain';
      const formatted = type.toLowerCase().includes('json') ? JSON.stringify(JSON.parse(entry.responseBody), null, 2) : entry.responseBody;
      setContentType(type);
      const url = new URL(entry.url, 'http://wireforge.local');
      setMethod(entry.method);
      setPath(url.pathname + url.search);
      setMatchType('exact');
      setConditionText('');
      setResponseHeaderText('');
      setStatus(entry.status);
      setBody(formatted);
      setTab('Mock rules');
      setError('');
    } catch (e) { setError(e instanceof SyntaxError ? 'This response is not JSON. Create a JSON mock manually.' : String(e)); }
  }

  const query = filter.toLowerCase();
  const visible = entries.filter(entry => `${entry.method} ${entry.url} ${entry.status} ${entry.source}`.toLowerCase().includes(query) && (trafficType === 'All' || trafficType === 'HTTP' && replayMethods.includes(entry.method) || trafficType === 'WS' && entry.method === 'WS' || trafficType === 'Mock' && entry.source === 'mock' || trafficType === 'Errors' && entry.status >= 400));
  const selected = visible.find(entry => entry.id === selectedId);
  return <div className="app">
    <aside>
      <div className="brand"><span className="brand-mark"><Icon name="activity" size={21}/></span>WireForge</div>
      <nav aria-label="Main navigation">
        {['Traffic', 'Replay', 'Mock rules', 'Settings'].map(item =>
          <button aria-label={item} className={tab === item ? 'active' : ''} aria-current={tab === item ? 'page' : undefined} onClick={() => {setTab(item); setError('');}} key={item}><Icon name={{Traffic: 'activity', Replay: 'replay', 'Mock rules': 'layers', Settings: 'settings'}[item] || 'activity'}/><span>{item}</span>{item === 'Traffic' && <small>{entries.length}</small>}{item === 'Mock rules' && rules.length + socketRules.length > 0 && <small>{rules.length + socketRules.length}</small>}</button>
        )}
      </nav>
      <div className="sidebar-footer"><span className={`status-dot ${running ? 'online' : ''}`}/><div><strong>Local proxy</strong><span className="endpoint">127.0.0.1:8080</span></div><Icon name="shield" size={15}/></div>
    </aside>
    <main>
      <header className="app-header">
        <div className="page-heading"><Icon name={{Traffic: 'activity', Replay: 'replay', 'Mock rules': 'layers', Settings: 'settings'}[tab] || 'activity'} size={17}/><h1>{tab}</h1></div>
        <div className="actions">
          <span className={`connection-state ${running ? 'online' : ''}`} title={!desktop ? 'Desktop connection required for network operations' : 'Local proxy status'}>{!desktop ? 'Preview' : running ? 'Listening' : 'Stopped'}</span>
          <button className={running ? 'stop-button' : 'primary'} disabled={!desktop || !ready || busy || (!!startupWarning && !running)} onClick={toggleServer}><Icon name={running ? 'stop' : 'play'} size={13}/>{busy ? 'Working…' : running ? 'Stop proxy' : 'Start proxy'}</button>
        </div>
      </header>
      {startupWarning && <p role="alert" className="error">{startupWarning}</p>}
      {error && <p role="alert" className="error">{error}</p>}
      <div className="content">
      {tab === 'Traffic' ? <>
        <section className="toolbar application-toolbar">
          <span className="application-label"><Icon name="globe"/>Application</span>
          <input aria-label="Application URL" disabled={applicationOpen} placeholder="http://localhost:3000" value={applicationUrl} onChange={e => setApplicationUrl(e.target.value)} onKeyDown={e => {if (e.key === 'Enter' && desktop && ready && !openingApplication && !applicationOpen && !startupWarning) void applicationAction();}}/>
          <button className="open-app-button" disabled={!desktop || !ready || openingApplication || applicationOpen || !!startupWarning} onClick={() => void applicationAction()}>{openingApplication ? 'Working…' : 'Open app'}<Icon name="arrow" size={14}/></button>
          <button className="icon-button" title="Reload application" aria-label="Reload application" disabled={!desktop || !ready || openingApplication || !applicationOpen} onClick={() => void applicationAction('reload')}><Icon name="refresh"/></button>
          <button className="icon-button" title="Close application" aria-label="Close application" disabled={!desktop || !ready || openingApplication || !applicationOpen} onClick={() => void applicationAction('close')}><Icon name="x"/></button>
        </section>
        <section className="toolbar traffic-toolbar">
          <div className="search-field"><Icon name="search" size={15}/><input aria-label="Filter traffic" placeholder="Search requests…" value={filter} onChange={e => setFilter(e.target.value)}/></div>
          <div className="filter-tabs" aria-label="Traffic type">{['All', 'HTTP', 'WS', 'Mock', 'Errors'].map(type => <button key={type} aria-pressed={trafficType === type} className={trafficType === type ? 'active' : ''} onClick={() => setTrafficType(type)}>{type}</button>)}</div>
          <button className="icon-button clear-button" title="Clear traffic" aria-label="Clear traffic" disabled={!ready || busy || entries.length === 0} onClick={clearTraffic}><Icon name="trash" size={15}/></button>
        </section>
        <div className={`traffic-layout ${selected ? 'with-detail' : ''}`} style={{'--list-fraction': `${trafficSplit}fr`, '--detail-fraction': `${100 - trafficSplit}fr`} as CSSProperties}>
          <section className="table" aria-label="Captured traffic">
            <div className="table-title"><strong>Requests <span>{visible.length}</span></strong><span><span className={`status-dot ${running || applicationOpen ? 'online' : ''}`}/>{running || applicationOpen ? 'Live capture' : 'Idle'}</span></div>
            <div className="columns table-head"><span>Method</span><span>Request</span><span>Status</span><span>Time</span><span className="extra-column">Source</span><span className="extra-column">Size</span></div>
            <div className="table-body">
              {visible.length ? visible.map(entry =>
                <button className={`traffic-row columns ${selectedId === entry.id ? 'selected' : ''}`} key={entry.id} onClick={() => {setSelectedId(entry.id); setDetailTab(entry.method === 'WS' ? 'Messages' : 'Response');}}>
                  <span><span className={`method method-${entry.method.toLowerCase()}`}>{entry.method}</span></span><span className="request-cell" title={entry.url}><strong>{addressParts(entry.url).path}</strong><small>{addressParts(entry.url).host || entry.source}</small></span><span><span className={`status-badge ${entry.status >= 400 ? 'failed' : entry.status >= 200 && entry.status < 300 ? 'success' : ''}`}>{entry.status || (['streaming', 'connecting'].includes(entry.bodyState) ? '…' : '—')}</span></span><span className="timing">{entry.status ? `${entry.durationMs} ms` : '—'}</span><span className={`extra-column source source-${entry.source}`}>{entry.source}</span><span className="extra-column timing">{entry.responseBytes < 1024 ? `${entry.responseBytes} B` : `${(entry.responseBytes / 1024).toFixed(1)} kB`}</span>
                </button>
              ) : <EmptyState title={filter || trafficType !== 'All' ? 'No matching requests' : running || applicationOpen ? 'Listening for traffic' : 'Ready to inspect'} detail={filter || trafficType !== 'All' ? 'Try a different filter.' : running || applicationOpen ? 'Requests will appear here.' : 'Start the proxy or open an application.'}/>}
            </div>
          </section>
          {selected && <div className="panel-divider" role="separator" aria-label="Resize request details" aria-orientation="vertical" aria-valuemin={30} aria-valuemax={70} aria-valuenow={trafficSplit} tabIndex={0} onKeyDown={event => {if (event.key === 'ArrowLeft' || event.key === 'ArrowRight') {event.preventDefault(); setTrafficSplit(value => Math.max(30, Math.min(70, value + (event.key === 'ArrowRight' ? 2 : -2))));}}} onPointerDown={event => {event.currentTarget.focus(); event.currentTarget.setPointerCapture(event.pointerId);}} onPointerMove={event => {if (event.buttons !== 1) return; const rect = event.currentTarget.parentElement!.getBoundingClientRect(); setTrafficSplit(Math.max(30, Math.min(70, (event.clientX - rect.left) / rect.width * 100)));}}/>}
          {selected && <section className="inspector" aria-label="Request details">
            <div className="inspector-kicker"><Icon name="code" size={14}/><span>Request details</span><button className="icon-button" aria-label="Close details" onClick={() => setSelectedId(undefined)}><Icon name="x" size={15}/></button></div>
            <div className="inspector-heading"><span className={`method method-${selected.method.toLowerCase()}`}>{selected.method}</span><strong title={selected.url}>{addressParts(selected.url).path}<small>{addressParts(selected.url).host}</small></strong></div>
            <div className="metadata"><span>{selected.status || '—'}</span><span title="Time to response headers">{selected.durationMs} ms</span><span>{selected.source}</span><span>{selected.responseBytes.toLocaleString()} B</span></div>
            <div className="detail-tabs">{(selected.method === 'WS' ? ['Messages', 'Headers'] : ['Response', 'Request', 'Headers']).map(item => <button key={item} className={detailTab === item ? 'active' : ''} onClick={() => setDetailTab(item)}>{item}</button>)}</div>
            <div className="inspector-body">
              {detailTab === 'Messages' ? <>
                <div className="metadata"><span>{selected.bodyState}</span>{selected.messagesDropped > 0 && <span>{selected.messagesDropped} older messages omitted</span>}</div>
                {selected.responseBody && <p className="error">{selected.responseBody}</p>}
                {selected.messages.length ? selected.messages.map((message, index) => <div className="socket-message" key={index}>
                  <div className="metadata"><span className={message.direction === 'in' ? 'success' : ''}>{message.direction === 'in' ? '↓ In' : '↑ Out'}</span><span>{message.elapsedMs} ms</span><span>{message.bytes.toLocaleString()} B</span><span>{message.kind === 'mock' ? 'Mock' : message.kind === 'blocked' ? 'Blocked' : 'Wire'}</span><span>{message.opcode === 1 ? 'Text' : `Base64 · ${message.opcode}`}</span>{message.truncated && <span>Preview</span>}
                    <button disabled={message.truncated || ![1, 2].includes(message.opcode)} onClick={() => {setSocketPayload(message.payload); setSocketBinary(message.opcode === 2); setSocketDraft(undefined);}}>Use</button>
                    <button disabled={message.truncated || message.opcode !== 1 || !!startupWarning} onClick={() => {setSocketDraft({direction: message.direction, matchText: message.payload}); setSocketPayload(message.payload); setSocketBinary(false);}}>Mock</button>
                  </div>
                  <pre>{message.payload || 'Empty'}</pre>
                </div>) : <span className="muted">No messages</span>}
                <div className="socket-composer">
                  {socketDraft && <label>{socketDraft.direction === 'out' ? 'Local reply · exact outgoing match' : 'Replace incoming · exact match'}<textarea rows={2} aria-label="WebSocket match" value={socketDraft.matchText} onChange={event => setSocketDraft({...socketDraft, matchText: event.target.value})}/></label>}
                  <textarea aria-label="WebSocket payload" rows={3} placeholder={socketDraft ? 'Mock response' : 'Message'} maxLength={131072} value={socketPayload} onChange={event => setSocketPayload(event.target.value)}/>
                  <div className="form-actions"><select aria-label="WebSocket payload format" disabled={!!socketDraft} value={socketBinary ? 'base64' : 'text'} onChange={event => setSocketBinary(event.target.value === 'base64')}><option value="text">Text</option><option value="base64">Base64</option></select>
                    {socketDraft ? <><button disabled={socketBusy || !desktop || !ready || !!startupWarning} onClick={() => void updateSocketRules([...socketRules, {id: crypto.randomUUID(), url: selected.url, ...socketDraft, responseText: socketPayload, enabled: true}])}>Save rule</button><button onClick={() => setSocketDraft(undefined)}>Cancel</button></> : <>
                      <button disabled={socketBusy || !applicationOpen || !selected.socketControl || selected.bodyState !== 'open'} onClick={() => void socketAction('send', selected.id)}>Send</button>
                      <button disabled={socketBusy || !applicationOpen || !selected.socketControl || selected.bodyState !== 'open'} onClick={() => void socketAction('inject', selected.id)}>Inject</button>
                    </>}
                  </div>
                  {!!socketRules.filter(rule => rule.url === selected.url).length && <details><summary>Socket rules</summary>{renderSocketRules(socketRules.filter(rule => rule.url === selected.url))}</details>}
                </div>
              </> : detailTab === 'Response' ? <>
                <div className="metadata"><span>{selected.bodyState}</span>{selected.responseTruncated && <span>16 KiB preview</span>}</div>
                <CodeView value={selected.responseBody || (['streaming', 'decoding'].includes(selected.bodyState) ? 'Loading…' : 'Empty body')}/>
              </> : detailTab === 'Request' ? <>
                {selected.requestTruncated && <span className="muted">16 KiB preview</span>}<CodeView value={selected.requestBody || 'Empty body'}/>
              </> : <><h3>Request</h3><HeaderList headers={selected.requestHeaders}/><h3>Response</h3><HeaderList headers={selected.responseHeaders}/></>}
            </div>
            <div className="inspector-actions">
              <button title="Replay HTTP or HTTPS" disabled={!replayMethods.includes(selected.method) || selected.requestHeaders.some(([name]) => name === 'preview')} onClick={() => draftReplay(selected)}><Icon name="replay" size={14}/>Replay</button>
              <button disabled={selected.bodyState !== 'complete' || selected.responseTruncated || !selected.responseAvailable || ['CONNECT', 'WS', 'CAPTURE'].includes(selected.method)} onClick={() => draftMock(selected)}><Icon name="layers" size={14}/>Create mock</button>
            </div>
          </section>}
        </div>
      </> : tab === 'Replay' ? <section className="editor panel">
        <div className="request-line">
          <label>Method<select value={replayMethod} onChange={e => setReplayMethod(e.target.value)}>{replayMethods.map(value => <option key={value}>{value}</option>)}</select></label>
          <label>URL<input placeholder="https://service.local/api" value={replayUrl} onChange={e => setReplayUrl(e.target.value)}/></label>
          <button className="primary" title="Send through the local proxy and configured upstream route" disabled={!desktop || !ready || !running || busy || replayLoading || (replayNeedsOriginal && !replayFile && !replayBody.length)} onClick={sendReplay}>Send<Icon name="arrow" size={14}/></button>
        </div>
        <div className="editor-columns">
          <label><span className="editor-label">Headers <small>JSON pairs</small></span><textarea disabled={busy || replayLoading} spellCheck={false} value={replayHeaders} onChange={e => setReplayHeaders(e.target.value)}/></label>
          <div className="replay-body">
            <div className="body-tools"><span id="replay-body-label">Body</span><select aria-label="Replay body encoding" title="Interpret the body as UTF-8 text or Base64 encoded bytes" disabled={busy || replayLoading || !!replayFile} value={replayBodyEncoding} onChange={e => setReplayBodyEncoding(e.target.value as 'text' | 'base64')}><option value="text">Text</option><option value="base64">Base64</option></select>
              <button disabled={busy || replayLoading} onClick={() => replayFileInput.current?.click()}>{replayLoading ? 'Loading…' : 'Load file'}</button>
              <input ref={replayFileInput} type="file" hidden aria-label="Load replay body from file" onChange={e => {const file = e.target.files?.[0]; e.target.value = ''; if (file) void loadReplayFile(file);}}/>
            </div>
            {replayFile ? <div className="replay-file"><span title={replayFile.name}>{replayFile.name}</span><small>{replayFile.size.toLocaleString()} B</small><button disabled={busy || replayLoading} onClick={() => {replayFileBody.current = undefined; setReplayFile(undefined);}}>Remove</button></div> : <textarea aria-labelledby="replay-body-label" disabled={busy || replayLoading} spellCheck={false} value={replayBody} onChange={e => setReplayBody(e.target.value)}/>}
            {replayNeedsOriginal && !replayFile && !replayBody.length && <span className="muted">Original body required</span>}
          </div>
        </div>
        {replayMessage && <p role="status" className="notice">{replayMessage}</p>}
      </section> : tab === 'Mock rules' ? <div className="mock-layout">
        <section className="panel mock-editor">
          <div className="section-heading"><h2>Response rule</h2><span>HTTP</span></div>
          <div className="form-row rule-match-row">
            <label>Method<select value={method} onChange={e => setMethod(e.target.value)}>{['ANY', 'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'].map(value => <option key={value}>{value}</option>)}</select></label>
            <label>Match<select value={matchType} onChange={e => setMatchType(e.target.value as MatchType)}>{(Object.keys(matchLabels) as MatchType[]).map(value => <option key={value} value={value}>{matchLabels[value]}</option>)}</select></label>
            <label>Status<input type="number" min="200" max="599" value={status} onChange={e => setStatus(Number(e.target.value))}/></label>
          </div>
          <label>Path<input value={path} spellCheck={false} onChange={e => setPath(e.target.value)} title={pathHints[matchType]} placeholder={pathHints[matchType]}/></label>
          <label>Content type<input value={contentType} onChange={e => setContentType(e.target.value)}/></label>
          <details className="rule-advanced" open={!!conditionText || !!responseHeaderText}>
            <summary>Header conditions and response headers</summary>
            <label>Request must include<textarea rows={3} spellCheck={false} value={conditionText} onChange={e => setConditionText(e.target.value)} placeholder={'X-Tenant: acme-*\nAuthorization'} title="One header per line. * matches any characters in the value. A name without a value only requires the header."/></label>
            <label>Response headers<textarea rows={3} spellCheck={false} value={responseHeaderText} onChange={e => setResponseHeaderText(e.target.value)} placeholder={'Cache-Control: no-store\nX-Mocked-By: wireforge'} title="One Name: value per line. Content-Type uses the field above."/></label>
          </details>
          <label>Response<textarea rows={12} spellCheck={false} value={body} onChange={e => setBody(e.target.value)}/></label>
          <button className="primary" disabled={!ready || busy || !!startupWarning} onClick={addRule}>Add rule</button>
        </section>
        <section className="panel rule-list" aria-label="Saved mock rules">
          <div className="table-title"><strong>Saved rules <span>{rules.length + socketRules.length}</span></strong><Icon name="layers" size={14}/></div>
          {socketRules.length > 0 && <details><summary>WebSocket rules · {socketRules.length}</summary>{renderSocketRules(socketRules)}</details>}
          {rules.length ? rules.map(rule => <article key={rule.id}>
            <div className="rule-heading"><strong className={!rule.enabled ? 'muted' : ''}>{rule.method} {rule.path}</strong>{(rule.matchType ?? 'exact') !== 'exact' && <span className="badge">{matchLabels[rule.matchType!]}</span>}{!!rule.requestHeaders?.length && <span className="badge" title={rule.requestHeaders.map(pair => pair.value ? `${pair.name}: ${pair.value}` : pair.name).join('\n')}>{rule.requestHeaders.length} cond.</span>}<span className="badge">{rule.status}</span></div>
            <div className="rule-actions"><button disabled={!ready || busy || !!startupWarning} onClick={() => void updateRules(rules.map(item => item.id === rule.id ? {...item, enabled: !item.enabled} : item))}>{rule.enabled ? 'Disable' : 'Enable'}</button><button disabled={!ready || busy || !!startupWarning} onClick={() => void updateRules(rules.filter(item => item.id !== rule.id))}>Delete</button><details><summary>Body</summary><pre>{rule.body}</pre></details></div>
          </article>) : <EmptyState title="No HTTP mock rules" detail="Create a rule or use a captured response." icon="layers"/>}
        </section>
      </div> : <div className="settings-grid">
        <section className="panel">
          <h2 className="card-heading"><span className="card-icon"><Icon name="route" size={18}/></span>Upstream proxy</h2>
          {running && <p className="muted">Stop proxy to edit.</p>}
          <fieldset disabled={running || applicationOpen || busy || !desktop || !ready || !!startupWarning} title={applicationOpen ? 'Close the application window to change the upstream proxy' : undefined}>
            <label className="checkbox"><input type="checkbox" checked={upstream.enabled} onChange={e => {setUpstream({...upstream, enabled: e.target.checked}); setSettingsMessage('');}}/> Enabled</label>
            {upstream.enabled && <>
              <div className="upstream-fields"><label>Host<input placeholder="proxy.company.local" autoComplete="off" value={upstream.host} onChange={e => setUpstream({...upstream, host: e.target.value})}/></label><label>Port<input type="number" min="1" max="65535" value={upstream.port} onChange={e => setUpstream({...upstream, port: Number(e.target.value)})}/></label></div>
              <label className="checkbox"><input type="checkbox" checked={upstream.basicAuth} onChange={e => setUpstream({...upstream, basicAuth: e.target.checked})}/> Basic auth</label>
              {upstream.basicAuth && <><label>Username<input autoComplete="off" value={upstream.username} onChange={e => setUpstream({...upstream, username: e.target.value})}/></label><label>Password<input type="password" autoComplete="new-password" placeholder={upstream.passwordConfigured ? 'Unchanged if empty' : 'Password'} value={password} onChange={e => setPassword(e.target.value)}/></label><small className="muted">HTTP Basic · session password</small></>}
            </>}
            <div className="form-actions"><button className="primary" onClick={saveUpstream}>Save</button></div>
          </fieldset>
          {settingsMessage && <p role="status" className="notice">{settingsMessage}</p>}
        </section>
        <section className="panel">
          <div className="section-heading"><h2 className="card-heading"><span className="card-icon"><Icon name="shield" size={18}/></span>HTTPS inspection</h2><span className="muted">HTTP/1.1</span></div>
          {tlsWarning && <p role="alert" className="error">{tlsWarning}</p>}
          <fieldset disabled={running || busy || !desktop || !ready || !!startupWarning}>
            <label className="checkbox"><input type="checkbox" checked={tlsEnabled} onChange={e => setTlsEnabled(e.target.checked)}/> Enabled</label>
            <label className="checkbox"><input type="checkbox" checked={allHosts} onChange={e => setAllHosts(e.target.checked)}/> All HTTPS hosts</label>
            {!allHosts && <label>Targets (host:port)<textarea rows={4} spellCheck={false} placeholder="api.company.local:443" value={tlsTargets} onChange={e => setTlsTargets(e.target.value)}/></label>}
            <div className="form-actions"><button className="primary" onClick={saveTls}>Save</button><button onClick={prepareCa}>{ca ? 'Reload CA' : 'Create CA'}</button></div>
          </fieldset>
          {tlsMessage && <p role="status" className="notice">{tlsMessage}</p>}
          <details className="certificate-details"><summary>Certificate {ca ? `· ${ca.keyProtection}` : '· required'}</summary>
            <p className="muted">Trust the public CA in your test client. Pinned certificates may reject inspection.</p>
            {ca && <><p className="workspace-path">{ca.certificatePath}</p><label>SHA-256<code className="fingerprint">{ca.fingerprint}</code></label><button onClick={copyCa}>Copy certificate</button><p className="muted">User-bound key. Share only the public certificate.</p></>}
          </details>
        </section>
        <details className="panel workspace-details"><summary>Workspace</summary><p className="workspace-path">{workspacePath || 'Desktop storage'}</p></details>
      </div>}
      </div>
    </main>
  </div>;
}

createRoot(document.getElementById('root')!).render(<App/>);
