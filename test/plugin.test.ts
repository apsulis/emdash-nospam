import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// EmDash's definePlugin validates and normalises; the plugin logic under test is ours.
vi.mock("emdash", () => ({ definePlugin: (definition: unknown) => definition }));

const { createPlugin } = await import("../src/plugin.js");
const { record, registry } = await import("../src/stats.js");
const { fetchToken, readyToken, withToken } = await import("../src/client.js");

type Plugin = Record<string, any>;

function fakeCtx(user?: { role: number }) {
	const store = new Map<string, { value: unknown; revision: string }>();
	let n = 0;
	const kv = {
		get: async (k: string) => store.get(k)?.value ?? null,
		getVersioned: async (k: string) => store.get(k) ?? null,
		compareAndSet: async (k: string, expected: string | null, value: unknown) => {
			if ((store.get(k)?.revision ?? null) !== expected) return { applied: false };
			const revision = String(++n);
			store.set(k, { value, revision });
			return { applied: true, revision };
		},
	};
	const logs: string[] = [];
	const log = (m: string) => logs.push(m);
	return { store, logs, ctx: { user, kv, log: { info: log, warn: log, error: log, debug: log } } as any };
}

beforeEach(() => {
	const r = registry();
	r.counts = {};
	r.flushed = {};
	r.recent = [];
	r.endpoints.clear();
});

describe("plugin widget", () => {
	const plugin = createPlugin() as Plugin;
	const render = (ctx: unknown) => plugin.routes.admin.handler(ctx);

	it("is reserved to administrators", async () => {
		expect(await render(fakeCtx({ role: 40 }).ctx)).toEqual({ blocks: [{ type: "context", text: "Administrators only." }] });
		expect(await render(fakeCtx(undefined).ctx)).toEqual({ blocks: [{ type: "context", text: "Administrators only." }] });
	});

	it("persists totals once, shows counts, reasons and recent refusals", async () => {
		const { ctx, store } = fakeCtx({ role: 50 });
		registry().endpoints.set("forms", { name: "forms", settings: "delay 3 s to 120 min", secret: "derived from EMDASH_ENCRYPTION_KEY", clientIp: "from x-forwarded-for", untrustedForward: false });
		record({ at: "2026-10-20T10:00:00.000Z", endpoint: "forms", form: "contact", action: "accept", reasons: [] });
		record({ at: "2026-10-20T10:01:00.000Z", endpoint: "forms", form: "contact", action: "reject", reasons: ["honeypot"] });
		const first = await render(ctx);
		await render(ctx);
		expect(store.get("state:totals")?.value).toEqual({ accept: 1, reject: 1, "reason:honeypot": 1 });
		const stats = first.blocks.find((b: any) => b.type === "stats");
		expect(stats.items.map((i: any) => [i.label, i.value])).toEqual([["Accepted", 1], ["Flagged", 0], ["Rejected", 1]]);
		const fields = first.blocks.find((b: any) => b.type === "fields").fields;
		expect(fields.find((f: any) => f.label === "Reasons (all time)").value).toBe("honeypot 1");
		const table = first.blocks.find((b: any) => b.type === "table");
		expect(table.rows).toEqual([{ at: "2026-10-20T10:01:00.000Z", form: "forms / contact", action: "reject", reasons: "honeypot" }]);
		expect(first.blocks.some((b: any) => b.type === "banner")).toBe(false);
	});

	it("warns about an untrusted proxy and a random key", async () => {
		registry().endpoints.set("forms", { name: "forms", settings: "", secret: "random key (resets on restart)", clientIp: "socket address", untrustedForward: true });
		const { blocks } = await render(fakeCtx({ role: 50 }).ctx);
		expect(blocks.filter((b: any) => b.type === "banner").map((b: any) => b.title)).toEqual(["forms: client IP unknown behind your proxy", "forms: random signing key"]);
	});
});

describe("client", () => {
	afterEach(() => {
		vi.useRealTimers();
		vi.unstubAllGlobals();
	});

	it("fetches a token, refreshes an expiring one and waits for the minimum delay", async () => {
		vi.useFakeTimers();
		let served = 0;
		vi.stubGlobal("fetch", async () => new Response(JSON.stringify({ token: `t${++served}`, field: "nospam_token", honeypot: "website_url", minSeconds: 3, maxAgeSeconds: 7200 })));
		const first = await fetchToken("/api/forms/contact");
		expect(first).toMatchObject({ token: "t1", field: "nospam_token" });
		const ready = readyToken(first, "/api/forms/contact");
		await vi.advanceTimersByTimeAsync(3300);
		expect((await ready).token).toBe("t1");
		vi.setSystemTime(Date.now() + 7200 * 1000);
		const renewed = readyToken(first, "/api/forms/contact");
		await vi.advanceTimersByTimeAsync(3300);
		expect((await renewed).token).toBe("t2");
		expect(withToken({ nom: "Jean" }, first)).toEqual({ nom: "Jean", nospam_token: "t1" });
	});

	it("fails clearly on a bad answer", async () => {
		vi.stubGlobal("fetch", async () => new Response("nope", { status: 404 }));
		await expect(fetchToken("/x")).rejects.toThrow(/HTTP 404/);
	});
});
