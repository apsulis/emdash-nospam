# @apsulis/emdash-nospam

CAPTCHA-free anti-spam for the forms of **self-hosted [EmDash](https://github.com/emdash-cms/emdash)** sites
(Node.js): contact forms, sign-ups, any endpoint of yours that turns a visitor's post into an email or a record.

- **No CAPTCHA, no third party, no cookie, no dependency.** Nothing to rent, nothing to show to visitors, nothing to
  declare in a privacy policy beyond what your form already collects.
- **Layered checks, cheapest first:** a honeypot field, the user agent, a signed timing token (bound to the form and
  the browser, neither too young nor too old), a per-IP rate limit, then the content (links, BBCode, hidden markup,
  blocked words, unexpected alphabets).
- **Graded verdicts:** bots get a silent fake success, people get a clear message when they must retry or wait, and
  borderline messages are *flagged* rather than lost, so that you deliver them marked.
- **Works with static fronts:** the form fetches its token from your endpoint, cross-origin if needed.
- **Private by design:** IPs are only kept as keyed pseudonyms, in memory, for the rate-limit window; field values
  are never logged.
- A dashboard widget for administrators: accepted / flagged / rejected counts, reasons, last refusals, and warnings
  when the setup is wrong (untrusted proxy, random key).

EmDash already protects its own **comments** (honeypot, optional Turnstile, rate limit, `comment:moderate` hook).
This plugin is for everything else: the forms you write yourself.

## Install

```bash
pnpm add @apsulis/emdash-nospam
```

```js
// astro.config.mjs — the dashboard widget
import emdash from "emdash/astro";
import emdashNospam from "@apsulis/emdash-nospam";

export default defineConfig({
	integrations: [emdash({ /* … */ plugins: [emdashNospam()] })],
});
```

Behind a reverse proxy (Apache, nginx, a load balancer), tell EmDash — and this plugin — which header carries the
visitor's IP, or every visitor will share one rate-limit bucket (the widget warns you):

```dotenv
EMDASH_TRUSTED_PROXY_HEADERS=x-forwarded-for
```

## Protect an endpoint

The checks run where your form is handled. An Astro API route, answering `GET` with a token and `POST` with the
submission:

```ts
// src/pages/api/contact.ts
import type { APIRoute } from "astro";
import { createNospam, messageFor } from "@apsulis/emdash-nospam";

export const prerender = false;

const nospam = createNospam({ name: "contact", allowedScripts: ["Latin"] });

export const GET: APIRoute = ({ request }) =>
	Response.json(nospam.token("contact", request), { headers: { "Cache-Control": "no-store" } });

export const POST: APIRoute = async ({ request, clientAddress }) => {
	const body = await request.json();
	const verdict = await nospam.check("contact", request, body, { clientAddress });
	if (verdict.reply === "silent") return Response.json({ ok: true }); // a bot: it learns nothing
	if (verdict.reply !== "ok") return Response.json({ ok: false, error: messageFor(verdict, "en") }, { status: 429 });
	const subject = verdict.action === "flag" ? "[Spam?] New message" : "New message";
	// … validate verdict.data (the body without the token and the honeypot), then send or store it.
	return Response.json({ ok: true });
};
```

A page rendered on the server can put `nospam.token(…)` straight into hidden inputs. A static or client-rendered
form gets it from the `GET`, for instance with the tiny browser helper:

```js
import { fetchToken, readyToken, withToken, HONEYPOT_FIELD, HONEYPOT_STYLE } from "@apsulis/emdash-nospam/client";

let nospam = null;
form.addEventListener("focusin", async () => (nospam ??= await fetchToken("/api/contact")), { once: true });
form.addEventListener("submit", async (event) => {
	event.preventDefault();
	nospam = await readyToken(nospam, "/api/contact"); // renews an expiring token, waits for the minimum delay
	const body = withToken(Object.fromEntries(new FormData(form)), nospam);
	await fetch("/api/contact", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
});
```

```html
<!-- the honeypot, left empty by people -->
<div style="position:absolute;left:-10000px;top:auto;width:1px;height:1px;overflow:hidden" aria-hidden="true">
	<label>Leave this field empty <input name="website_url" tabindex="-1" autocomplete="off"></label>
</div>
```

For a cross-origin front, answer CORS on the endpoint (`GET` needs no preflight; the JSON `POST` does).

## What is checked

| Order | Check | Verdict | Reply |
|---|---|---|---|
| 1 | Honeypot filled | reject `honeypot` | `silent` |
| 2 | Empty user agent, or an HTTP library / headless browser | reject `user-agent` | `silent` |
| 3 | Token absent / forged or for another form or browser | reject `token-missing` / `token-invalid` | `retry` / `silent` |
| 4 | Token younger than `minSeconds` (3) / older than `maxAgeSeconds` (2 h) | reject `too-fast` / `token-expired` | `retry` |
| 5 | More than `max` (5) messages per `windowSeconds` (10 min) from the same IP — counted only after 1-4 | reject `rate-limit` | `limit` |
| 6 | BBCode links, hidden markup (`display:none`…), a blocked word, 6 links or more | reject | `silent` |
| 7 | 3 to 5 links, a link in a short one-line field, HTML, mostly unexpected letters | flag | `ok` |

`reply` tells you how to answer: `ok` deliver (`action` is `accept` or `flag`), `silent` pretend it worked, `retry`
ask to send again (`messageFor(verdict, "en" | "fr")`), `limit` ask to wait `retryAfter` seconds.

## Options

| Option | Default | |
|---|---|---|
| `name` | `"forms"` | endpoint name in the widget and logs |
| `secret` | `NOSPAM_SECRET`, else derived from `EMDASH_ENCRYPTION_KEY` | 16 characters or more; the signing key is derived from it (HKDF) |
| `minSeconds` / `maxAgeSeconds` | `3` / `7200` | token age window |
| `bindUserAgent` | `true` | a token only works in the browser it was given to |
| `tokenField` / `honeypotField` | `"nospam_token"` / `"website_url"` | body field names |
| `blockedUserAgents` | HTTP libraries, headless browsers | a `RegExp`, or `false` |
| `rateLimit` | `{ max: 5, windowSeconds: 600, unknownMax: 20 }` | or `false`; `unknownMax` is the shared bucket when the IP is unknown |
| `links` | `{ flag: 3, reject: 6 }` | links in the whole message, or `false` |
| `shortFieldLinks` | `"flag"` | `"reject"` or `"ignore"` |
| `blockedWords` | `[]` | whole words, case and accents ignored |
| `allowedScripts` | none | Unicode scripts, e.g. `["Latin"]`: mostly other letters → flag |
| `trustedProxyHeaders` | `EMDASH_TRUSTED_PROXY_HEADERS` | for `X-Forwarded-For`, its **last** entry is used (the one your proxy added) |
| `store` | in memory | a `RateLimitStore` (`hit(key, windowSeconds, now)`) for several processes |
| `log` | `console.info` | one line per refusal or flag, never a value; `false` to silence |

`check(form, request, body, { clientAddress, fields })`: `fields` limits the content checks to some body fields (leave
out a legitimate « website » field).

## Limits

- The rate-limit counters and the widget's « since start » figures live in memory: right for a single Node process
  (EmDash on SQLite runs one), reset at restart. Totals are saved in the plugin's storage when an administrator
  opens the dashboard. Several processes or servers: provide a shared `store`.
- Tokens are not single-use: replaying one within its lifetime is bounded by the rate limit, not refused.
- No CAPTCHA, no DNS blocklists, no Akismet-like service, no machine learning. If a determined spammer gets
  through, add `blockedWords`, tighten `links`, or put a CAPTCHA in front of that one form.
- Node.js only (it uses `node:crypto`), like EmDash on a server.

## Credits

The layered approach — honeypot, timed token bound to the form, links counted per message, flood control — comes from
the [SPIP « nospam » plugin](https://git.spip.net/spip-contrib-extensions/nospam) (Cédric Morin, GPL); this is an
independent implementation for EmDash. The `website_url` honeypot name follows EmDash's own comment form.

## License

MIT © Apsulis
