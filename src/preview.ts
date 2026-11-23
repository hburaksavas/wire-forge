// Development-only visual fixtures, enabled explicitly with ?preview.
const examples = [
  ['GET', '/v1/projects?limit=20', 200, 42, 'webview', {projects: [{id: 'prj_01', name: 'Commerce API', environment: 'staging', status: 'healthy'}, {id: 'prj_02', name: 'Identity service', environment: 'staging', status: 'healthy'}], total: 2}],
  ['POST', '/v1/auth/session', 201, 86, 'forwarded', {authenticated: true, expiresIn: 3600}],
  ['GET', '/v1/users/me', 200, 4, 'mock', {id: 'usr_demo', name: 'Alex Morgan', role: 'developer', permissions: ['requests:read', 'mocks:write'], active: true}],
  ['GET', '/v1/catalog/products?page=1', 200, 128, 'forwarded', {items: [], page: 1}],
  ['PATCH', '/v1/projects/prj_01', 200, 67, 'webview', {updated: true}],
  ['GET', '/v1/payments/summary', 502, 301, 'forwarded', {error: 'Upstream unavailable', code: 'GATEWAY_ERROR'}],
  ['OPTIONS', '/v1/users/me', 204, 2, 'mock', ''],
  ['GET', '/v1/notifications?unread=true', 200, 23, 'worker', {unread: 3}],
] as const;

export function createPreviewEntries() { return examples.map(([method, path, status, durationMs, source, response], index) => ({
  id: index + 1, revision: index + 1, method, url: `https://api.staging.example.test${path}`, status, durationMs, source,
  responseBody: typeof response === 'string' ? response : JSON.stringify(response), requestBody: method === 'PATCH' ? '{"name":"Commerce API"}' : '',
  requestHeaders: [['accept', 'application/json'], ['host', 'api.staging.example.test'], ['user-agent', 'WireForge design preview']] as [string, string][],
  responseHeaders: [['content-type', 'application/json'], ['cache-control', 'no-store'], ['x-request-id', `req_preview_${index + 1}`]] as [string, string][],
  bodyState: 'complete', requestTruncated: false, responseTruncated: false, responseBytes: typeof response === 'string' ? 0 : JSON.stringify(response).length,
  requestAvailable: true, responseAvailable: true, socketControl: false, messages: [], messagesDropped: 0,
})); }
