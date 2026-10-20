import { afterEach, describe, expect, it } from "vitest";

import { blockedWordsPattern, inspect, scriptsPattern, type ContentRules } from "../src/content.js";
import { clientIp, normaliseIp, trustedHeaders } from "../src/ip.js";
import { MemoryStore } from "../src/rate-limit.js";
import { agentDigest, issueToken, resolveSecret, verifyToken } from "../src/token.js";

const ENV = ["NOSPAM_SECRET", "EMDASH_ENCRYPTION_KEY", "EMDASH_TRUSTED_PROXY_HEADERS"];
afterEach(() => ENV.forEach((k) => delete process.env[k]));

describe("secret", () => {
	it("prefers the option, then NOSPAM_SECRET, then EMDASH_ENCRYPTION_KEY, else a random key", () => {
		process.env.EMDASH_ENCRYPTION_KEY = "emdash-encryption-key-0123456789";
		expect(resolveSecret().source).toBe("EMDASH_ENCRYPTION_KEY");
		process.env.NOSPAM_SECRET = "nospam-secret-0123456789";
		expect(resolveSecret().source).toBe("NOSPAM_SECRET");
		expect(resolveSecret("option-secret-0123456789").source).toBe("option");
		ENV.forEach((k) => delete process.env[k]);
		expect(resolveSecret().source).toBe("random");
	});

	it("derives the key: same secret, same key; never the secret itself", () => {
		const a = resolveSecret("option-secret-0123456789").key;
		expect(a.equals(resolveSecret("option-secret-0123456789").key)).toBe(true);
		expect(a.toString("utf8")).not.toContain("option-secret");
	});

	it("refuses a short secret", () => {
		expect(() => resolveSecret("short")).toThrow(/too short/);
	});
});

describe("token", () => {
	const key = resolveSecret("option-secret-0123456789").key;
	const agent = agentDigest("Mozilla/5.0");

	it("verifies a token of the same form and agent, with its issue time", () => {
		const token = issueToken(key, "contact", agent, 1_700_000_000_000);
		expect(verifyToken(key, token, "contact", agent)).toEqual({ ok: true, issuedAt: 1_700_000_000_000 });
	});

	it("refuses another form, another agent, another key, a tampered or missing token", () => {
		const token = issueToken(key, "contact", agent, Date.now());
		expect(verifyToken(key, token, "newsletter", agent)).toEqual({ ok: false, reason: "token-invalid" });
		expect(verifyToken(key, token, "contact", agentDigest("curl/8"))).toEqual({ ok: false, reason: "token-invalid" });
		expect(verifyToken(resolveSecret("another-secret-0123456789").key, token, "contact", agent).ok).toBe(false);
		const [p, at, nonce, sig] = token.split(".");
		expect(verifyToken(key, [p, (Number.parseInt(at!, 36) - 60_000).toString(36), nonce, sig].join("."), "contact", agent).ok).toBe(false);
		expect(verifyToken(key, "", "contact", agent)).toEqual({ ok: false, reason: "token-missing" });
		expect(verifyToken(key, undefined, "contact", agent)).toEqual({ ok: false, reason: "token-missing" });
		expect(verifyToken(key, "x".repeat(500), "contact", agent)).toEqual({ ok: false, reason: "token-invalid" });
	});
});

describe("client IP", () => {
	const req = (headers: Record<string, string>) => new Request("http://localhost/", { headers });

	it("reads trusted headers from EMDASH_TRUSTED_PROXY_HEADERS", () => {
		process.env.EMDASH_TRUSTED_PROXY_HEADERS = " X-Forwarded-For , x-real-ip";
		expect(trustedHeaders()).toEqual(["x-forwarded-for", "x-real-ip"]);
		expect(trustedHeaders(["CF-Connecting-IP"])).toEqual(["cf-connecting-ip"]);
	});

	it("takes the LAST X-Forwarded-For entry, the one the proxy appended", () => {
		expect(clientIp(req({ "x-forwarded-for": "6.6.6.6, 203.0.113.7" }), ["x-forwarded-for"])).toEqual({ ip: "203.0.113.7", untrustedForward: false });
	});

	it("uses the socket address without proxy, nothing behind an untrusted proxy", () => {
		expect(clientIp(req({}), [], "198.51.100.1")).toEqual({ ip: "198.51.100.1", untrustedForward: false });
		expect(clientIp(req({ "x-forwarded-for": "203.0.113.7" }), [], "10.0.0.1")).toEqual({ ip: null, untrustedForward: true });
	});

	it("normalises: mapped IPv4, IPv6 /64, junk", () => {
		expect(normaliseIp("::ffff:192.0.2.1")).toBe("192.0.2.1");
		expect(normaliseIp("2001:db8:abcd:12:1:2:3:4")).toBe("2001:db8:abcd:12::/64");
		expect(normaliseIp("[2001:db8::1]")).toBe("2001:db8:0:0::/64");
		expect(normaliseIp("2001:db8:abcd:12::99")).toBe(normaliseIp("2001:db8:abcd:12:ffff::1"));
		expect(normaliseIp("not an ip")).toBeNull();
		expect(normaliseIp("1.2.3.4; drop table")).toBeNull();
	});
});

describe("memory store", () => {
	it("counts per key within a window, then starts over", () => {
		const store = new MemoryStore();
		expect([1, 2, 3].map(() => store.hit("a", 60, 1000))).toEqual([1, 2, 3]);
		expect(store.hit("b", 60, 1000)).toBe(1);
		expect(store.hit("a", 60, 61_001)).toBe(1);
	});
});

describe("content", () => {
	const rules = (over: Partial<ContentRules> = {}): ContentRules => ({
		links: { flag: 3, reject: 6 },
		shortFieldLinks: "flag",
		blockedWords: null,
		allowedScripts: null,
		...over,
	});
	const long = (text: string) => `Bonjour,\n${text}\nCordialement`;

	it("accepts an ordinary message, even with one link", () => {
		expect(inspect(["Jean", long("Notre site https://exemple.fr est à refaire.")], rules())).toEqual({ reject: [], flag: [] });
	});

	it("flags then rejects many links", () => {
		const links = (n: number) => long(Array.from({ length: n }, (_, i) => `https://spam${i}.example/x`).join(" "));
		expect(inspect([links(3)], rules()).flag).toContain("links");
		expect(inspect([links(6)], rules()).reject).toContain("links");
		expect(inspect([links(9)], rules({ links: false }))).toEqual({ reject: [], flag: [] });
	});

	it("handles a link in a short field according to the option", () => {
		expect(inspect(["www.cheap-pills.example"], rules()).flag).toEqual(["link-in-short-field"]);
		expect(inspect(["www.cheap-pills.example"], rules({ shortFieldLinks: "reject" })).reject).toEqual(["link-in-short-field"]);
		expect(inspect(["www.cheap-pills.example"], rules({ shortFieldLinks: "ignore" })).flag).toEqual([]);
	});

	it("rejects BBCode and hidden content, flags HTML", () => {
		expect(inspect([long("[url=https://x.example]x[/url]")], rules()).reject).toContain("bbcode");
		expect(inspect([long('<div style="display:none">buy</div>')], rules()).reject).toContain("hidden-content");
		expect(inspect([long('<a href="https://x.example">x</a>')], rules()).flag).toContain("markup");
	});

	it("rejects blocked words, whole words, accents and case ignored", () => {
		const blockedWords = blockedWordsPattern(["casino", "Crédit rapide"]);
		expect(inspect([long("Best CASINO bonus")], rules({ blockedWords })).reject).toEqual(["blocked-word"]);
		expect(inspect([long("un credit RAPIDE sans frais")], rules({ blockedWords })).reject).toEqual(["blocked-word"]);
		expect(inspect([long("Casinos de Monaco")], rules({ blockedWords })).reject).toEqual([]);
	});

	it("flags mostly unexpected scripts", () => {
		const allowedScripts = scriptsPattern(["Latin"]);
		expect(inspect([long("Купить дешевые лекарства онлайн без рецепта")], rules({ allowedScripts })).flag).toEqual(["script"]);
		expect(inspect([long("Bonjour, je m'appelle Ивaн et je cherche un devis.")], rules({ allowedScripts })).flag).toEqual([]);
		expect(() => scriptsPattern(["Klingon"])).toThrow();
	});
});
