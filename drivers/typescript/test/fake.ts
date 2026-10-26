// SPDX-License-Identifier: Apache-2.0
// Scriptable hostile fake server + a lossy TCP proxy for regression tests.
import * as net from "net";

export type Reply =
  | { ok?: unknown; err?: string }          // a normal JSON frame
  | { raw: Buffer | string }                // an arbitrary frame body
  | { frames: unknown[] }                   // several frames for ONE request
  | { hdr: number }                         // only a (lying) length header, then silence
  | { big: number }                         // a valid {"ok":{"x":"aaa..."}} frame of ~n bytes, in 1 KiB writes
  | "drop" | "hang";

export type Handler = (method: string, args: any[], n: number) => Reply;

export interface Fake {
  port: number;
  /** methods seen, in order */
  seen: string[];
  /** raw request bodies, in order */
  bodies: string[];
  /** push unsolicited bytes to every connected client */
  push(b: Buffer): void;
  close(): void;
}

const frame = (b: Buffer) => { const h = Buffer.alloc(4); h.writeUInt32BE(b.length); return Buffer.concat([h, b]); };

export const HELLO = { ok: { protocol: 2, server: "fake", auth_required: false, max_frame: 33554432, persistent: false } };

export async function fake(handler: Handler): Promise<Fake> {
  const seen: string[] = [], bodies: string[] = [];
  const socks = new Set<net.Socket>();
  const counts = new Map<string, number>();
  const server = net.createServer((sock) => {
    socks.add(sock);
    sock.on("error", () => {});
    sock.on("close", () => socks.delete(sock));
    let buf = Buffer.alloc(0);
    sock.on("data", (c) => {
      buf = Buffer.concat([buf, c]);
      while (buf.length >= 4 && buf.length >= 4 + buf.readUInt32BE(0)) {
        const n = buf.readUInt32BE(0);
        const body = buf.subarray(4, 4 + n).toString();
        buf = buf.subarray(4 + n);
        const req = JSON.parse(body);
        seen.push(req.m); bodies.push(body);
        const k = (counts.get(req.m) ?? 0) + 1; counts.set(req.m, k);
        const out = handler(req.m, req.a, k);
        if (out === "drop") { sock.destroy(); return; }
        if (out === "hang") continue;
        if ("hdr" in (out as any)) { const h = Buffer.alloc(4); h.writeUInt32BE((out as any).hdr); sock.write(h); continue; }
        if ("big" in (out as any)) {
          const total = (out as any).big;
          const pre = Buffer.from('{"ok":{"x":"'), suf = Buffer.from('"}}');
          const len = pre.length + total + suf.length;
          const h = Buffer.alloc(4); h.writeUInt32BE(len);
          sock.write(h); sock.write(pre);
          const kb = Buffer.alloc(1024, 97);
          for (let left = total; left > 0; left -= 1024) sock.write(left >= 1024 ? kb : kb.subarray(0, left));
          sock.write(suf);
          continue;
        }
        if ("raw" in (out as any)) { sock.write(frame(Buffer.from((out as any).raw))); continue; }
        if ("frames" in (out as any)) {
          sock.write(Buffer.concat((out as any).frames.map((f: unknown) => frame(Buffer.from(JSON.stringify(f))))));
          continue;
        }
        sock.write(frame(Buffer.from(JSON.stringify(out))));
      }
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return {
    port: (server.address() as net.AddressInfo).port, seen, bodies,
    push: (b) => socks.forEach((s) => s.write(b)),
    close: () => { socks.forEach((s) => s.destroy()); server.close(); },
  };
}

/** Default responses for a one-table fake: t(id plain, v encrypted). */
export function base(over: Record<string, Reply | ((a: any[], n: number) => Reply)> = {}): Handler {
  return (m, a, n) => {
    const o = over[m];
    if (o !== undefined) return typeof o === "function" ? o(a, n) : o;
    switch (m) {
      case "hello": return HELLO;
      case "tables": return { ok: [] };
      case "create": case "tx_begin": case "tx_commit": case "tx_rollback": case "update_cell": return { ok: null };
      case "ping": return { ok: "pong" };
      default: return { ok: null };
    }
  };
}

/** TCP proxy in front of a real server that can lose replies / refuse connections. */
export interface Proxy {
  port: number;
  /** For the next connection's FIRST request named `method`: "reply" = forward the
   *  request, swallow the reply and cut the client; "request" = cut the client
   *  without forwarding. One-shot. */
  lose(method: string, what: "reply" | "request", down?: boolean): void;
  /** stop accepting and cut every client connection */
  pause(): void;
  resume(): Promise<void>;
  close(): void;
}

export async function proxy(target: { host: string; port: number }): Promise<Proxy> {
  let rule: { method: string; what: "reply" | "request"; down: boolean } | null = null;
  let self: { pause(): void } | null = null;
  const conns = new Set<net.Socket>();
  let server: net.Server;
  const make = () => net.createServer((client) => {
    const up = net.connect(target.port, target.host);
    conns.add(client); conns.add(up);
    client.on("error", () => {}); up.on("error", () => {});
    client.on("close", () => { up.destroy(); conns.delete(client); });
    up.on("close", () => { client.destroy(); conns.delete(up); });
    let cbuf = Buffer.alloc(0), ubuf = Buffer.alloc(0);
    let swallow = false, downAfter = false;
    client.on("data", (c) => {
      cbuf = Buffer.concat([cbuf, c]);
      while (cbuf.length >= 4 && cbuf.length >= 4 + cbuf.readUInt32BE(0)) {
        const n = cbuf.readUInt32BE(0);
        const fr = cbuf.subarray(0, 4 + n);
        cbuf = cbuf.subarray(4 + n);
        const m = JSON.parse(fr.subarray(4).toString()).m;
        if (rule && rule.method === m) {
          const r = rule; rule = null;
          if (r.what === "request") { client.destroy(); up.destroy(); return; }
          swallow = true; downAfter = r.down;
        }
        up.write(fr);
      }
    });
    up.on("data", (c) => {
      if (swallow) {                          // the server answered; the client never hears it
        ubuf = Buffer.concat([ubuf, c]);
        if (ubuf.length >= 4 && ubuf.length >= 4 + ubuf.readUInt32BE(0)) { client.destroy(); up.destroy(); if (downAfter) self!.pause(); }
        return;
      }
      client.write(c);
    });
  });
  server = make();
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as net.AddressInfo).port;
  const p: Proxy = {
    port,
    lose: (method, what, down = false) => { rule = { method, what, down }; },
    pause: () => { server.close(); conns.forEach((s) => s.destroy()); conns.clear(); },
    resume: () => new Promise<void>((r) => { server = make(); server.listen(port, "127.0.0.1", () => r()); }),
    close: () => { server.close(); conns.forEach((s) => s.destroy()); },
  };
  self = p;
  return p;
}

/** One raw RPC to a real server (acts as the "lying server" / another client). */
export async function rawRpc(port: number, method: string, args: unknown[], token?: string): Promise<any> {
  const sock = net.connect(port, "127.0.0.1");
  await new Promise((r) => sock.once("connect", r));
  const call = (m: string, a: unknown[]) => new Promise<any>((res) => {
    const body = Buffer.from(JSON.stringify({ m, a }));
    let buf = Buffer.alloc(0);
    const on = (c: Buffer) => {
      buf = Buffer.concat([buf, c]);
      if (buf.length >= 4 && buf.length >= 4 + buf.readUInt32BE(0)) { sock.off("data", on); res(JSON.parse(buf.subarray(4).toString())); }
    };
    sock.on("data", on);
    sock.write(frame(body));
  });
  try {
    if (token) await call("auth", [token]);
    return await call(method, args);
  } finally { sock.destroy(); }
}

/** A recording pass-through proxy in front of a real server: every request (method + args) is logged in
 *  order, as the server receives it; `mutate` may rewrite a reply (a lying server). */
export interface Recorder {
  port: number;
  log: Array<{ m: string; a: any[] }>;
  close(): void;
}

export async function recorder(target: { host: string; port: number },
                               mutate?: (m: string, a: any[], reply: any, nth: number) => any): Promise<Recorder> {
  const log: Array<{ m: string; a: any[] }> = [];
  const conns = new Set<net.Socket>();
  const counts = new Map<string, number>();
  const server = net.createServer((client) => {
    const up = net.connect(target.port, target.host);
    conns.add(client); conns.add(up);
    client.on("error", () => {}); up.on("error", () => {});
    client.on("close", () => { up.destroy(); conns.delete(client); });
    up.on("close", () => { client.destroy(); conns.delete(up); });
    let cbuf = Buffer.alloc(0), ubuf = Buffer.alloc(0);
    const pending: Array<{ m: string; a: any[] }> = [];
    client.on("data", (c) => {
      cbuf = Buffer.concat([cbuf, c]);
      while (cbuf.length >= 4 && cbuf.length >= 4 + cbuf.readUInt32BE(0)) {
        const n = cbuf.readUInt32BE(0);
        const fr = cbuf.subarray(0, 4 + n);
        cbuf = cbuf.subarray(4 + n);
        const req = JSON.parse(fr.subarray(4).toString());
        log.push({ m: req.m, a: req.a });
        pending.push({ m: req.m, a: req.a });
        up.write(fr);
      }
    });
    up.on("data", (c) => {
      ubuf = Buffer.concat([ubuf, c]);
      while (ubuf.length >= 4 && ubuf.length >= 4 + ubuf.readUInt32BE(0)) {
        const n = ubuf.readUInt32BE(0);
        let fr = ubuf.subarray(0, 4 + n);
        ubuf = ubuf.subarray(4 + n);
        const req = pending.shift();
        if (mutate && req) {
          const k = (counts.get(req.m) ?? 0) + 1; counts.set(req.m, k);
          const reply = JSON.parse(fr.subarray(4).toString());
          const out = mutate(req.m, req.a, reply, k);
          if (out !== reply) fr = frame(Buffer.from(JSON.stringify(out)));
        }
        client.write(fr);
      }
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return {
    port: (server.address() as net.AddressInfo).port, log,
    close: () => { server.close(); conns.forEach((s) => s.destroy()); },
  };
}
