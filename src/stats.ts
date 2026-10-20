/**
 * Process-wide record of the verdicts, read by the dashboard widget. Kept on globalThis: form endpoints and the
 * plugin are loaded separately by the bundler, possibly as two copies of this module. Never any field value nor IP.
 */

export type Action = "accept" | "flag" | "reject";

export interface StatEvent {
	at: string;
	endpoint: string;
	form: string;
	action: Action;
	reasons: string[];
}

export interface EndpointSummary {
	name: string;
	settings: string;
	secret: string;
	clientIp: string;
	/** An untrusted X-Forwarded-For header was seen: rate limiting falls back to one shared bucket. */
	untrustedForward: boolean;
}

export interface Registry {
	startedAt: string;
	endpoints: Map<string, EndpointSummary>;
	/** `accept`, `flag`, `reject` and `reason:<reason>` counters since the start of the process. */
	counts: Record<string, number>;
	/** Part of `counts` already added to the persistent totals by the widget. */
	flushed: Record<string, number>;
	recent: StatEvent[];
}

const KEY = Symbol.for("emdash-nospam:registry");
const RECENT = 20;

export function registry(): Registry {
	const g = globalThis as Record<symbol, Registry | undefined>;
	return (g[KEY] ??= { startedAt: new Date().toISOString(), endpoints: new Map(), counts: {}, flushed: {}, recent: [] });
}

export function record(event: StatEvent): void {
	const r = registry();
	const add = (key: string) => (r.counts[key] = (r.counts[key] ?? 0) + 1);
	add(event.action);
	for (const reason of event.reasons) add(`reason:${reason}`);
	if (event.action !== "accept") {
		r.recent.unshift(event);
		r.recent.length = Math.min(r.recent.length, RECENT);
	}
}

/** Counts not yet persisted, marked as persisted at once (the caller adds them to its totals). */
export function takeUnflushed(): Record<string, number> {
	const r = registry();
	const delta: Record<string, number> = {};
	for (const [key, value] of Object.entries(r.counts)) {
		const diff = value - (r.flushed[key] ?? 0);
		if (diff > 0) delta[key] = diff;
		r.flushed[key] = value;
	}
	return delta;
}
