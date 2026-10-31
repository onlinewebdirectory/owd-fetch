# owd-fetch: check before you fetch

A drop-in `fetch` for AI agents. Before fetching a website it asks [Online Web Directory](https://onlinewebdirectory.net) how that site treats agents; after fetching it reports what it actually saw, so every agent that uses it makes the directory better for the next one.

- Knows 30,000+ sites: bot walls (Cloudflare, Akamai, DataDome, PerimeterX), JavaScript needs, robots rules, rate limits, and llms.txt, feeds, sitemaps and APIs to use instead of scraping.
- Never breaks your fetch: if the directory is slow, down or out of free lookups, the fetch just goes ahead.
- Respects owners: if a site's robots.txt tells all agents to stay out, it does not fetch unless you pass `force`. Everything else is fetched, with warnings.
- Free: 10 lookups a day without a key, 100 a day once it has made its own key (no sign-up).

## JavaScript (Node 18+, no dependencies)

```bash
npm install @onlinewebdirectory/fetch
```

```js
import { owdFetch } from "@onlinewebdirectory/fetch";

const res = await owdFetch("https://g2.com/");
res.owd.warnings; // [{ code: "robots_partial" }, { code: "machine_interface_available", path: "/llms.txt" }]
res.owd.page;     // "https://onlinewebdirectory.net/sites/g2.com"
```

## Python (3.9+)

```bash
pip install onlinewebdirectory
```

```python
import onlinewebdirectory as owd

r = owd.get("https://g2.com/")
r.owd["warnings"]  # [{"code": "robots_partial"}, {"code": "machine_interface_available", "path": "/llms.txt"}]
r.status, r.text
```

## What you get back

`owd.warnings` (a list, empty when nothing is unusual):

| code | meaning |
| --- | --- |
| `machine_interface_available` | the site offers llms.txt, a feed, a sitemap or an API (`path`) to use instead of scraping |
| `needs_browser` | a plain HTTP client meets a bot wall or a JavaScript wall (`expect_challenge` names the vendor) |
| `site_blocks_agents` | the site blocks, asks for a login or a payment (`reason`); fetched anyway |
| `robots_partial` | robots.txt restricts some paths; check the path you need |
| `directory_unavailable` | the directory did not answer in time; fetched without hints |

`owd.page` is the site's page in the directory, so your agent can cite where it learned this. `owd.strategy` is the directory's full advice (`plain_http`, `headless_required`, `use_machine_interface`, `do_not_fetch`).

When robots.txt disallows all agents, JavaScript throws `OwdRefused` and Python raises `owd.Refused` (with `host`, `reason` and `page`). Pass `force: true` / `force=True` to fetch anyway.

## Any other client or framework

Use the two hooks around your own HTTP call:

```js
import { before, after } from "@onlinewebdirectory/fetch";
const advice = await before(url);                       // { fetch, warnings, page, strategy }
await after(url, { status, headers, body });            // reports what you saw
```

```python
advice = owd.before(url)
owd.after(url, status, headers, body)
```

## Options

| JavaScript | Python | default | |
| --- | --- | --- | --- |
| `force` | `force` | false | fetch even when robots.txt disallows all agents |
| `report` | `report` | true | report what was seen (also `OWD_REPORT=0`) |
| `lookup` | `lookup` | true | ask the directory first |
| `timeoutMs` | `timeout` | 1500 ms / 1.5 s | how long to wait for the directory |
| `fetch` | `fetch` | platform fetch / urllib | your own HTTP function |

## Privacy

Only the hostname is sent for a lookup. A report sends the hostname and typed facts (for example `access_posture=bot_challenged`, `challenge_vendor=cloudflare`), signed with this machine's own key. Never the path, query, page content, headers, cookies or anything you sent. The key lives in `~/.config/onlinewebdirectory/key.json` (shared with the Online Web Directory skill; `OWD_HOME` moves it). Turn reporting off with `report: false` or `OWD_REPORT=0`.

## More

- Look a site up in your browser: `https://onlinewebdirectory.net/sites/<host>`
- MCP server: `https://onlinewebdirectory.net/mcp`
- Agent skill: `npx skills add onlinewebdirectory/onlinewebdirectory-skill`
- Open data (CC BY 4.0): https://github.com/onlinewebdirectory/agent-web-data
