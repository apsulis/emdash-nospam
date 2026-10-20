import { beforeEach, describe, expect, it } from "vitest";

import { createNospam, messageFor, type NospamOptions } from "../src/server.js";
import { registry } from "../src/stats.js";

const UA = "Mozilla/5.0 (Macintosh) Firefox/140.0";
const SECRET = "test-secret-0123456789";

function setup(options: NospamOptions = {}) {
	let clock = 1_800_000_000_000;
	const lines: string[] = [];
	const nospam = createNospam({ secret: SECRET, log: (l) => lines.push(l), now: () => clock, ...options });
	const request = (headers: Record<string, string> = {}) => new Request("http://localhost/api/forms/contact", { method: "POST", headers: { "user-agent": UA, ...headers } });
	const tick = (seconds: number) => (clock += seconds * 1000);
	const submit = async (body: Record<string, unknown>, headers?: Record<string, string>, wait = 5) => {
		const { token, field } = nospam.token("contact", request(headers));
		tick(wait);
		return nospam.check("contact", request(headers), { [field]: token, ...body }, { clientAddress: "198.51.100.1" });
	};
	return { nospam, request, tick, submit, lines };
}

const message = { nom: "Jean Dupont", message: "Bonjour,\nje voudrais un devis pour notre site.\nMerci" };

beforeEach(() => {
	const r = registry();
	r.counts = {};
	r.flushed = {};
	r.recent = [];
	r.endpoints.clear();
});

describe("createNospam", () => {
	it("accepts a normal submission and strips its own fields", async () => {
		const { submit } = setup();
		const verdict = await submit({ ...message, website_url: "" });
		expect(verdict).toMatchObject({ action: "accept", reply: "ok", reasons: [] });
		expect(verdict.data).toEqual(message);
	});

	it("answers bots silently: honeypot, tool user agent, empty user agent, forged token", async () => {
		const { submit, nospam, request } = setup();
		expect(await submit({ ...message, website_url: "http://spam.example" })).toMatchObject({ action: "reject", reply: "silent", reasons: ["honeypot"] });
		expect(await submit(message, { "user-agent": "python-requests/2.32" })).toMatchObject({ reply: "silent", reasons: ["user-agent"] });
		expect(await submit(message, { "user-agent": "" })).toMatchObject({ reply: "silent", reasons: ["user-agent"] });
		expect(await nospam.check("contact", request(), { ...message, nospam_token: "n1.abc.def.ghi" })).toMatchObject({ reply: "silent", reasons: ["token-invalid"] });
	});

	it("asks a person to retry: no token, too fast, expired", async () => {
		const { submit, nospam, request } = setup();
		const missing = await nospam.check("contact", request(), message);
		expect(missing).toMatchObject({ reply: "retry", reasons: ["token-missing"] });
		expect(messageFor(missing, "fr")).toMatch(/recharger la page/);
		expect(await submit(message, {}, 1)).toMatchObject({ reply: "retry", reasons: ["too-fast"] });
		expect(await submit(message, {}, 7201)).toMatchObject({ reply: "retry", reasons: ["token-expired"] });
	});

	it("refuses a token issued for another form or browser", async () => {
		const { nospam, request, tick } = setup();
		const { token } = nospam.token("newsletter", request());
		tick(5);
		expect((await nospam.check("contact", request(), { ...message, nospam_token: token })).reasons).toEqual(["token-invalid"]);
		const mine = nospam.token("contact", request()).token;
		tick(5);
		expect((await nospam.check("contact", request({ "user-agent": "Mozilla/5.0 Other" }), { ...message, nospam_token: mine })).reasons).toEqual(["token-invalid"]);
	});

	it("limits submissions per IP, behind a trusted proxy, with a retry delay", async () => {
		const { submit } = setup({ trustedProxyHeaders: ["x-forwarded-for"], rateLimit: { max: 2, windowSeconds: 600 } });
		const from = (ip: string) => ({ "x-forwarded-for": `1.1.1.1, ${ip}` });
		expect((await submit(message, from("203.0.113.1"))).action).toBe("accept");
		expect((await submit(message, from("203.0.113.1"))).action).toBe("accept");
		const third = await submit(message, from("203.0.113.1"));
		expect(third).toMatchObject({ action: "reject", reply: "limit", reasons: ["rate-limit"], retryAfter: 600 });
		expect(messageFor(third, "en")).toMatch(/Too many messages/);
		expect((await submit(message, from("203.0.113.2"))).action).toBe("accept");
	});

	it("does not count bots against the limit", async () => {
		const { submit } = setup({ rateLimit: { max: 1 } });
		for (let i = 0; i < 5; i++) await submit({ ...message, website_url: "x" });
		expect((await submit(message)).action).toBe("accept");
	});

	it("puts unknown IPs (untrusted proxy) in one larger bucket, and says so", async () => {
		const { submit } = setup({ rateLimit: { max: 1, unknownMax: 3 } });
		const proxied = { "x-forwarded-for": "203.0.113.9" };
		for (let i = 0; i < 3; i++) expect((await submit(message, proxied)).action).toBe("accept");
		expect((await submit(message, proxied)).reasons).toEqual(["rate-limit"]);
		expect([...registry().endpoints.values()][0]!.untrustedForward).toBe(true);
	});

	it("flags or rejects on content, only for the inspected fields", async () => {
		const { submit } = setup({ blockedWords: ["casino"] });
		expect(await submit({ ...message, nom: "www.pills.example" })).toMatchObject({ action: "flag", reply: "ok", reasons: ["link-in-short-field"] });
		expect(await submit({ ...message, message: "Best casino in town" })).toMatchObject({ action: "reject", reply: "silent", reasons: ["blocked-word"] });
	});

	it("logs refusals without any value, and records statistics", async () => {
		const { submit, lines } = setup({ name: "site" });
		await submit({ ...message, website_url: "spam@example.com" });
		await submit(message);
		expect(lines).toHaveLength(1);
		expect(lines[0]).toMatch(/^\[emdash-nospam\] site form=contact reject honeypot ip=[\w-]{8}$/);
		expect(lines.join()).not.toMatch(/Jean|spam@example|198\.51/);
		const r = registry();
		expect(r.counts).toMatchObject({ accept: 1, reject: 1, "reason:honeypot": 1 });
		expect(r.recent[0]).toMatchObject({ endpoint: "site", form: "contact", action: "reject", reasons: ["honeypot"] });
		expect(r.endpoints.get("site")?.secret).toBe("derived from the secret option");
	});

	it("checks its options", () => {
		expect(() => createNospam({ secret: SECRET, minSeconds: 10, maxAgeSeconds: 5 })).toThrow(/maxAgeSeconds/);
		expect(() => createNospam({ secret: SECRET, allowedScripts: ["Klingon"] })).toThrow();
		expect(() => createNospam({ secret: "short" })).toThrow(/too short/);
	});

	it("answers the token request with what the form needs", () => {
		const { nospam, request } = setup({ minSeconds: 2, maxAgeSeconds: 600 });
		expect(nospam.token("contact", request())).toMatchObject({ field: "nospam_token", honeypot: "website_url", minSeconds: 2, maxAgeSeconds: 600 });
	});
});
