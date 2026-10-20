import { definePlugin } from "emdash";
import type { PluginContext } from "emdash";

import { PLUGIN_ID, VERSION } from "./index.js";
import { registry, takeUnflushed } from "./stats.js";

const ADMIN = 50;
const TOTALS = "state:totals";
const RECENT_ROWS = 10;

type Caller = { role: number } | undefined;
type Totals = Record<string, number>;

/** Adds the counts of this process not yet persisted to the totals kept in the plugin's KV (atomic, retried). */
async function persistTotals(ctx: PluginContext): Promise<Totals> {
	const delta = takeUnflushed();
	for (let attempt = 0; attempt < 5; attempt++) {
		const current = await ctx.kv.getVersioned<Totals>(TOTALS);
		const next: Totals = { ...(current?.value ?? {}) };
		for (const [key, value] of Object.entries(delta)) next[key] = (next[key] ?? 0) + value;
		if (!Object.keys(delta).length) return next;
		const write = await ctx.kv.compareAndSet(TOTALS, current?.revision ?? null, next);
		if (write.applied) return next;
	}
	ctx.log.warn("could not save the anti-spam totals (concurrent updates), they will be added next time");
	const r = registry();
	for (const [key, value] of Object.entries(delta)) r.flushed[key] = (r.flushed[key] ?? 0) - value;
	return (await ctx.kv.get<Totals>(TOTALS)) ?? {};
}

const reasonsOf = (counts: Totals) =>
	Object.entries(counts)
		.filter(([key]) => key.startsWith("reason:"))
		.sort((a, b) => b[1] - a[1])
		.map(([key, value]) => `${key.slice(7)} ${value}`)
		.join(" · ") || "none";

async function widget(ctx: PluginContext) {
	const r = registry();
	const totals = await persistTotals(ctx);
	const since = (key: string) => r.counts[key] ?? 0;
	const endpoints = [...r.endpoints.values()];
	const blocks: unknown[] = [];

	for (const e of endpoints) {
		if (e.untrustedForward) {
			blocks.push({
				type: "banner",
				variant: "alert",
				title: `${e.name}: client IP unknown behind your proxy`,
				description: "X-Forwarded-For is received but not trusted, so every visitor shares one rate-limit bucket. Set EMDASH_TRUSTED_PROXY_HEADERS=x-forwarded-for.",
			});
		}
		if (e.secret.startsWith("random")) {
			blocks.push({ type: "banner", variant: "alert", title: `${e.name}: random signing key`, description: "Set NOSPAM_SECRET or EMDASH_ENCRYPTION_KEY: tokens are lost at each restart." });
		}
	}

	blocks.push({
		type: "stats",
		items: [
			{ label: "Accepted", value: totals.accept ?? 0, description: `${since("accept")} since start` },
			{ label: "Flagged", value: totals.flag ?? 0, description: `${since("flag")} since start` },
			{ label: "Rejected", value: totals.reject ?? 0, description: `${since("reject")} since start` },
		],
	});
	blocks.push({
		type: "fields",
		fields: [
			{
				label: "Protected endpoints",
				value: endpoints.length ? endpoints.map((e) => `${e.name}: ${e.settings}`).join("\n") : "none called since the last start",
			},
			{ label: "Reasons (all time)", value: reasonsOf(totals) },
			...(endpoints[0] ? [{ label: "Signing key", value: endpoints[0].secret }, { label: "Client IP", value: endpoints[0].clientIp }] : []),
			{ label: "Since", value: `${r.startedAt.slice(0, 16).replace("T", " ")} UTC (process start)` },
		],
	});
	blocks.push({
		type: "table",
		page_action_id: "recent",
		empty_text: "Nothing refused or flagged since the last start.",
		columns: [
			{ key: "at", label: "When", format: "relative_time" },
			{ key: "form", label: "Form" },
			{ key: "action", label: "Verdict", format: "badge" },
			{ key: "reasons", label: "Reasons" },
		],
		rows: r.recent.slice(0, RECENT_ROWS).map((e) => ({ at: e.at, form: `${e.endpoint} / ${e.form}`, action: e.action, reasons: e.reasons.join(", ") })),
	});
	return { blocks };
}

/** Native plugin: the « Anti-spam » dashboard widget, for administrators. No hook, no capability. */
export function createPlugin() {
	return definePlugin({
		id: PLUGIN_ID,
		version: VERSION,
		capabilities: [],
		admin: { widgets: [{ id: "status", title: "Anti-spam", size: "half" }] },
		routes: {
			admin: {
				// Every signed-in user may load the dashboard; only administrators see anything.
				permission: "content:read",
				handler: async (ctx) => {
					const user = ctx.user as Caller;
					if (!user || user.role < ADMIN) return { blocks: [{ type: "context", text: "Administrators only." }] };
					return widget(ctx);
				},
			},
		},
	});
}

export default createPlugin;
