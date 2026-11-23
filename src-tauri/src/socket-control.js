function(initialRules) {
  const key = '__wireforgeSocketControl_v1';
  if (globalThis[key]) { globalThis[key].setRules(initialRules); return; }
  const Native = globalThis.WebSocket;
  if (!Native) return;
  const send = Native.prototype.send;
  const dispatch = EventTarget.prototype.dispatchEvent;
  const sockets = new Map();
  const synthetic = new WeakSet();
  let sequence = 0;
  let rules = initialRules;
  const emit = value => {
    try { globalThis.__wireforgeSocketEvent(JSON.stringify(value)); } catch {}
  };
  const report = (id, direction, payload, kind) => {
    const size = new TextEncoder().encode(payload).length;
    // Native history retains a bounded preview; the application receives the full value.
    let preview = payload.slice(0, 2048);
    if (/^[\uDC00-\uDFFF]/.test(payload.slice(preview.length))) preview = preview.slice(0, -1);
    emit({type:'message', id, direction, opcode:1, payload:preview, bytes:size, truncated:preview.length < payload.length, kind});
  };
  const inject = (socket, id, payload, binary = false) => {
    if (socket.readyState !== Native.OPEN) throw new Error('Socket is not open');
    let data = payload;
    if (binary) {
      const bytes = Uint8Array.from(atob(payload), char => char.charCodeAt(0));
      data = socket.binaryType === 'arraybuffer' ? bytes.buffer : new Blob([bytes]);
    }
    const event = new MessageEvent('message', {data, origin:new URL(socket.url).origin});
    synthetic.add(event);
    Reflect.apply(dispatch, socket, [event]);
    if (!binary) report(id, 'in', payload, 'mock');
    else emit({type:'message',id,direction:'in',opcode:2,payload:payload.slice(0,4096),bytes:atob(payload).length,truncated:payload.length>4096,kind:'mock'});
  };
  const Wrapped = new Proxy(Native, {
    construct(target, args, newTarget) {
      const socket = Reflect.construct(target, args, newTarget === Wrapped ? target : newTarget);
      if (sockets.size >= 1000) return socket;
      const id = String(++sequence);
      sockets.set(id, socket);
      emit({type:'created', id, url:socket.url});
      Object.defineProperty(socket, 'send', {configurable:true, writable:true, value(payload) {
        if (this !== socket) return Reflect.apply(send, this, [payload]);
        if (socket.readyState === Native.OPEN && typeof payload === 'string') {
          const rule = rules.find(rule => rule.enabled && rule.url === socket.url && rule.direction === 'out' && rule.matchText === payload);
          if (rule) {
            report(id, 'out', payload, 'blocked');
            queueMicrotask(() => { if (socket.readyState === Native.OPEN) inject(socket,id,rule.responseText); });
            return;
          }
        }
        return Reflect.apply(send, socket, [payload]);
      }});
      socket.addEventListener('message', event => {
        if (synthetic.has(event) || typeof event.data !== 'string') return;
        const rule = rules.find(rule => rule.enabled && rule.url === socket.url && rule.direction === 'in' && rule.matchText === event.data);
        if (rule) { event.stopImmediatePropagation(); inject(socket,id,rule.responseText); }
      }, true);
      socket.addEventListener('close', () => sockets.delete(id), {once:true});
      return socket;
    }
  });
  Object.defineProperty(globalThis,key,{value:{
    setRules(value) { rules = value; },
    act(id, action, payload, binary) {
      const socket = sockets.get(id);
      if (!socket || socket.readyState !== Native.OPEN) throw new Error('Socket is closed or no longer available');
      if (action === 'inject') inject(socket,id,payload,binary);
      else if (action === 'send') {
        // Explicit sends go through the same mock rules as application sends.
        socket.send(binary ? Uint8Array.from(atob(payload),char=>char.charCodeAt(0)) : payload);
      } else throw new Error('Unknown socket action');
      return true;
    }
  }});
  globalThis.WebSocket = Wrapped;
}
