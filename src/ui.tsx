import {memo} from 'react';

const paths: Record<string, string> = {
  activity: 'M3 12h4l3-8 4 16 3-8h4',
  replay: 'M4 10a8 8 0 1 1 1 9M4 4v6h6M11 8l5 4-5 4z',
  layers: 'm12 3 9 5-9 5-9-5 9-5zm-9 9 9 5 9-5m-18 5 9 5 9-5',
  settings: 'M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8zm-2-5h4l1 3 3 1 3-1 2 4-2 2v3l1 2-3 3-3-1-2 2h-4l-1-3-3-1-2 1-2-4 2-2v-3L2 7l3-3 3 1z',
  play: 'm9 5 11 7-11 7z', stop: 'M6 6h12v12H6z',
  globe: 'M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0zM3 12h18M12 3a18 18 0 0 1 0 18 18 18 0 0 1 0-18z',
  refresh: 'M20 7v5h-5M4 17v-5h5M6 6a8 8 0 0 1 13 3M5 15a8 8 0 0 0 13 3',
  x: 'm6 6 12 12M6 18 18 6', search: 'M17 10a7 7 0 1 1-14 0 7 7 0 0 1 14 0zm-2 5 6 6',
  trash: 'M3 6h18M9 6V3h6v3M5 6l1 15h12l1-15M10 10v7m4-7v7',
  arrow: 'M4 12h16m-6-6 6 6-6 6', route: 'M6 5h9a4 4 0 0 1 0 8H9a4 4 0 0 0 0 8h9M3 5h3m12 16h3',
  shield: 'm12 3 8 3v6c0 5-8 9-8 9s-8-4-8-9V6l8-3zm-4 9 3 3 5-6',
  code: 'm8 6-6 6 6 6m8-12 6 6-6 6m-3-15-2 18',
  chevron: 'm9 5 7 7-7 7', copy: 'M8 8h13v13H8zM16 4V2H2v14h2',
};

export function Icon({name, size = 16}: {name: string; size?: number}) {
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.65" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d={paths[name] || paths.activity}/></svg>;
}

export function addressParts(address: string) {
  try {const url = new URL(address); if (!['http:', 'https:', 'ws:', 'wss:'].includes(url.protocol)) return {host: '', path: address}; return {host: url.host, path: url.pathname + url.search};}
  catch {return {host: '', path: address};}
}

export const CodeView = memo(function CodeView({value}: {value: string}) {
  let code = value;
  let json = false;
  try {code = JSON.stringify(JSON.parse(value), null, 2); json = true;} catch { /* Preserve non-JSON text. */ }
  return <pre className="code-view"><code>{code.split('\n').map((line, index) => <span className="code-line" key={index}><span className="line-number" aria-hidden="true">{index + 1}</span><span>{json ? line.split(/("(?:\\.|[^"\\])*"\s*:|"(?:\\.|[^"\\])*"|\b(?:true|false|null|-?\d+(?:\.\d+)?)\b)/g).map((token, part) => <span key={part} className={token.startsWith('"') ? token.endsWith(':') ? 'token-key' : 'token-string' : /^(true|false|null)$/.test(token) ? 'token-boolean' : /^-?\d/.test(token) ? 'token-number' : undefined}>{token}</span>) : line || ' '}</span></span>)}</code></pre>;
});

export function EmptyState({title, detail, icon = 'activity'}: {title: string; detail?: string; icon?: string}) {
  return <div className="empty"><div className="empty-glyph"><Icon name={icon} size={28}/></div><strong>{title}</strong>{detail && <span>{detail}</span>}</div>;
}
