// SPDX-License-Identifier: Apache-2.0
// A request/response proxy in front of the real server whose hooks can lie, swallow, kill or refuse.
import * as net from "net";

const frame = (b: Buffer) => { const h = Buffer.alloc(4); h.writeUInt32BE(b.length); return Buffer.concat([h, b]); };

export interface Hooks {
  /** return "kill" (drop both sockets), {reply} (answer without forwarding) or undefined (forward, possibly edited in place) */
  req?: (r: { m: string; a: any[] }) => "kill" | { reply: any } | undefined;
  /** return "drop" (forward the request but swallow the reply and kill the connection) or a replacement reply */
  resp?: (r: { m: string; a: any[] }, resp: any) => any;
}

export interface Proxy {
  port: number;
  hooks: Hooks;
  seen: string[];
  /** refuse new connections (the server is "unreachable") */
  refuse: { value: boolean };
  close(): void;
}

export async function startProxy(up: { host: string; port: number }): Promise<Proxy> {
  const seen: string[] = [];
  const refuse = { value: false };
  const px: Proxy = { port: 0, hooks: {}, seen, refuse, close: () => { server.close(); for (const s of socks) s.destroy(); } };
  const socks = new Set<net.Socket>();
  const server = net.createServer((cli) => {
    if (refuse.value) { cli.destroy(); return; }
    const upc = net.createConnection({ host: up.host, port: up.port });
    socks.add(cli); socks.add(upc);
    const kill = () => { cli.destroy(); upc.destroy(); };
    cli.on("error", () => undefined); upc.on("error", () => undefined);
    cli.on("close", () => upc.destroy()); upc.on("close", () => cli.destroy());
    let cbuf = Buffer.alloc(0), ubuf = Buffer.alloc(0);
    let waiting: { req: { m: string; a: any[] } } | null = null;
    cli.on("data", (d) => {
      cbuf = Buffer.concat([cbuf, d]);
      while (cbuf.length >= 4 && cbuf.length >= 4 + cbuf.readUInt32BE(0)) {
        const n = cbuf.readUInt32BE(0);
        const req = JSON.parse(cbuf.subarray(4, 4 + n).toString());
        cbuf = cbuf.subarray(4 + n);
        seen.push(req.m);
        const act = px.hooks.req?.(req);
        if (act === "kill") { kill(); return; }
        if (act && typeof act === "object") { cli.write(frame(Buffer.from(JSON.stringify(act.reply)))); continue; }
        waiting = { req };
        upc.write(frame(Buffer.from(JSON.stringify(req))));
      }
    });
    upc.on("data", (d) => {
      ubuf = Buffer.concat([ubuf, d]);
      while (ubuf.length >= 4 && ubuf.length >= 4 + ubuf.readUInt32BE(0)) {
        const n = ubuf.readUInt32BE(0);
        let rep = JSON.parse(ubuf.subarray(4, 4 + n).toString());
        ubuf = ubuf.subarray(4 + n);
        const w = waiting; waiting = null;
        if (w && px.hooks.resp) {
          const r = px.hooks.resp(w.req, rep);
          if (r === "drop") { kill(); return; }
          if (r !== undefined) rep = r;
        }
        cli.write(frame(Buffer.from(JSON.stringify(rep))));
      }
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  px.port = (server.address() as net.AddressInfo).port;
  return px;
}
