// A local stand-in for the directory and for target sites, recording every request.
import { createServer } from "node:http";

export async function startServer(handler) {
  const requests = [];
  const server = createServer(async (req, res) => {
    let body = "";
    for await (const chunk of req) body += chunk;
    const rec = { method: req.method, url: req.url, headers: req.headers, body };
    requests.push(rec);
    const out = await handler(rec);
    if (out?.hang) return; // never answers: lets a test exercise timeouts
    res.writeHead(out?.status ?? 200, out?.headers ?? { "Content-Type": "application/json" });
    res.end(typeof out?.body === "string" ? out.body : JSON.stringify(out?.body ?? {}));
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${server.address().port}`;
  return { base, requests, close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(r); }) };
}
