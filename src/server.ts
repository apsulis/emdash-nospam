import { blockedWordsPattern, type ContentReason, type ContentRules, inspect, scriptsPattern } from "./content.js";
import { clientIp, trustedHeaders } from "./ip.js";
import { MemoryStore, type RateLimitStore } from "./rate-limit.js";
import { type Action, record, registry } from "./stats.js";
import { agentDigest, ipKey, issueToken, resolveSecret, verifyToken } from "./token.js";

export type { RateLimitStore } from "./rate-limit.js";
export { MemoryStore } from "./rate-limit.js";

export type Reason =
	| "honeypot"
	| "user-agent"
	| "token-missing"
	| "token-invalid"
	| "token-expired"
	| "too-fast"
	| "rate-limit"
	| ContentReason;

/**
 * How to answer the visitor: `ok` (deliver), `silent` (a bot: answer as if it had worked, it learns nothing),
 * `retry` (maybe a person: ask to send again), `limit` (too many messages: ask to wait `retryAfter` seconds).
 */
export type Reply = "ok" | "silent" | "retry" | "limit";

export interface Verdict {
	/** `flag`: deliver, but mark it (subject prefix, moderation queue…). */
	action: Action;
	reply: Reply;
	reasons: Reason[];
	retryAfter?: number;
	/** The submitted values without the token and the honeypot. */
	data: Record<string, unknown>;
}

export interface NospamOptions {
	/** Name of this endpoint in the dashboard widget and the logs. Default `forms`. */
	name?: string;
	/** Signing secret (16 characters or more). Default: NOSPAM_SECRET, else derived from EMDASH_ENCRYPTION_KEY. */
	secret?: string;
	/** A token younger than this is refused (`too-fast`). Default 3. */
	minSeconds?: number;
	/** A token older than this is refused (`token-expired`). Default 7200 (2 h). */
	maxAgeSeconds?: number;
	/** Bind each token to the browser's user agent. Default true. */
	bindUserAgent?: boolean;
	/** Body field carrying the token. Default `nospam_token`. */
	tokenField?: string;
	/** Hidden field that people leave empty and bots fill. Default `website_url`. */
	honeypotField?: string;
	/** Refused user agents (an empty one always is). Default: HTTP libraries and headless browsers; false: none. */
	blockedUserAgents?: RegExp | false;
	/** Messages per IP: `max` per `windowSeconds`, `unknownMax` for the shared bucket of unknown IPs. False: off. */
	rateLimit?: { max?: number; windowSeconds?: number; unknownMax?: number } | false;
	/** Links in a message: flag from `flag` (default 3), reject from `reject` (default 6). False: not counted. */
	links?: { flag?: number; reject?: number } | false;
	/** A link in a short one-line field. Default `flag`. */
	shortFieldLinks?: "flag" | "reject" | "ignore";
	/** Words that reject a message (whole words, case and accents ignored). */
	blockedWords?: string[];
	/** Unicode scripts expected in messages (e.g. `["Latin"]`): mostly other letters → flag. Default: no check. */
	allowedScripts?: string[] | null;
	/** Headers carrying the client IP. Default: EMDASH_TRUSTED_PROXY_HEADERS, as EmDash. */
	trustedProxyHeaders?: string[];
	/** Rate-limit counters. Default: in memory (one Node process). */
	store?: RateLimitStore;
	/** One line per refused or flagged submission, without any value. Default console.info; false: silent. */
	log?: ((line: string) => void) | false;
	/** Clock, for tests. */
	now?: () => number;
}

/** What a form needs to post: answer it to `GET` requests of your endpoint (JSON, `Cache-Control: no-store`). */
export interface TokenResponse {
	token: string;
	/** Body field to send the token in. */
	field: string;
	/** Name of the hidden honeypot field to render (left empty). */
	honeypot: string;
	minSeconds: number;
	maxAgeSeconds: number;
}

export interface CheckOptions {
	/** Socket address of the request (Astro: `clientAddress`), used when no proxy sits in front. */
	clientAddress?: string | null;
	/** Body fields whose text is inspected (default: every string value). Leave out a « website » field. */
	fields?: string[];
}

export interface Nospam {
	/** A fresh token for `form` (any stable form identifier, e.g. its slug). */
	token(form: string, request: Request): TokenResponse;
	/** Verdict on a submission of `form`: the parsed body as posted, token and honeypot included. */
	check(form: string, request: Request, body: Record<string, unknown>, options?: CheckOptions): Promise<Verdict>;
}

const DEFAULT_AGENTS =
	/curl|wget|python-requests|python-urllib|aiohttp|httpx|go-http-client|okhttp|libwww-perl|java\/|scrapy|node-fetch|axios|^node$|headlesschrome|phantomjs|httpclient/i;

/** Bot checks answered as if it had worked; the other token checks may hit a person, who is asked to retry. */
const SILENT: ReadonlySet<Reason> = new Set<Reason>(["honeypot", "user-agent", "token-invalid"]);

/** Messages for the `retry` and `limit` replies. */
export const MESSAGES = {
	en: {
		"token-missing": "The form could not be verified. Please reload the page and send it again.",
		"token-expired": "The form has expired. Please send it again.",
		"too-fast": "Please wait a few seconds before sending the form.",
		"rate-limit": "Too many messages have been sent from your connection. Please try again in a few minutes.",
	},
	fr: {
		"token-missing": "Le formulaire n'a pas pu être vérifié. Merci de recharger la page et de l'envoyer à nouveau.",
		"token-expired": "Le formulaire a expiré. Merci de l'envoyer à nouveau.",
		"too-fast": "Merci de patienter quelques secondes avant d'envoyer le formulaire.",
		"rate-limit": "Trop de messages ont été envoyés depuis votre connexion. Merci de réessayer dans quelques minutes.",
	},
} as const;

/** Message to show for a verdict whose reply is `retry` or `limit`, else null. */
export function messageFor(verdict: Verdict, lang: keyof typeof MESSAGES = "en"): string | null {
	if (verdict.reply !== "retry" && verdict.reply !== "limit") return null;
	const reason = verdict.reasons[0] as keyof (typeof MESSAGES)["en"];
	return MESSAGES[lang][reason] ?? MESSAGES[lang]["token-missing"];
}

const positive = (value: number | undefined, fallback: number, name: string) => {
	const n = value ?? fallback;
	if (!Number.isFinite(n) || n < 0) throw new Error(`emdash-nospam: ${name} must be a positive number`);
	return n;
};

export function createNospam(options: NospamOptions = {}): Nospam {
	const name = options.name ?? "forms";
	const now = options.now ?? Date.now;
	const { key, source } = resolveSecret(options.secret);
	const minSeconds = positive(options.minSeconds, 3, "minSeconds");
	const maxAgeSeconds = positive(options.maxAgeSeconds, 7200, "maxAgeSeconds");
	if (maxAgeSeconds <= minSeconds) throw new Error("emdash-nospam: maxAgeSeconds must exceed minSeconds");
	const bindAgent = options.bindUserAgent ?? true;
	const tokenField = options.tokenField ?? "nospam_token";
	const honeypotField = options.honeypotField ?? "website_url";
	const agents = options.blockedUserAgents === undefined ? DEFAULT_AGENTS : options.blockedUserAgents;
	const limit =
		options.rateLimit === false
			? null
			: {
					max: positive(options.rateLimit?.max, 5, "rateLimit.max"),
					windowSeconds: positive(options.rateLimit?.windowSeconds, 600, "rateLimit.windowSeconds"),
					unknownMax: positive(options.rateLimit?.unknownMax, 20, "rateLimit.unknownMax"),
				};
	const store = options.store ?? new MemoryStore();
	const headers = trustedHeaders(options.trustedProxyHeaders);
	const rules: ContentRules = {
		links:
			options.links === false
				? false
				: { flag: positive(options.links?.flag, 3, "links.flag"), reject: positive(options.links?.reject, 6, "links.reject") },
		shortFieldLinks: options.shortFieldLinks ?? "flag",
		blockedWords: blockedWordsPattern(options.blockedWords ?? []),
		allowedScripts: scriptsPattern(options.allowedScripts),
	};
	const log = options.log === false ? () => {} : (options.log ?? ((line: string) => console.info(line)));
	if (source === "random") {
		console.warn(`[emdash-nospam] ${name}: no NOSPAM_SECRET nor EMDASH_ENCRYPTION_KEY, tokens are signed with a random key and die with the process`);
	}

	const summary = {
		name,
		settings: [
			`delay ${minSeconds} s to ${Math.round(maxAgeSeconds / 60)} min`,
			limit ? `${limit.max} per ${Math.round(limit.windowSeconds / 60)} min per IP` : "no rate limit",
			rules.links ? `links: flag ${rules.links.flag}, reject ${rules.links.reject}` : "links not counted",
			rules.blockedWords ? `${(options.blockedWords ?? []).length} blocked word(s)` : "",
			rules.allowedScripts ? `scripts: ${options.allowedScripts!.join(", ")}` : "",
		]
			.filter(Boolean)
			.join(" · "),
		secret: source === "random" ? "random key (resets on restart)" : `derived from ${source === "option" ? "the secret option" : source}`,
		clientIp: headers.length ? `from ${headers.join(", ")}` : "socket address",
		untrustedForward: false,
	};
	registry().endpoints.set(name, summary);

	const agentOf = (request: Request) => request.headers.get("user-agent")?.trim() ?? "";

	return {
		token(form, request) {
			return {
				token: issueToken(key, form, bindAgent ? agentDigest(agentOf(request)) : "", now()),
				field: tokenField,
				honeypot: honeypotField,
				minSeconds,
				maxAgeSeconds,
			};
		},

		async check(form, request, body, checkOptions = {}) {
			const data: Record<string, unknown> = { ...body };
			delete data[tokenField];
			delete data[honeypotField];
			const { ip, untrustedForward } = clientIp(request, headers, checkOptions.clientAddress);
			if (untrustedForward && !summary.untrustedForward) {
				summary.untrustedForward = true;
				console.warn(`[emdash-nospam] ${name}: X-Forwarded-For received but not trusted, set EMDASH_TRUSTED_PROXY_HEADERS=x-forwarded-for behind a proxy`);
			}
			const tag = ip ? ipKey(key, ip).slice(0, 8) : "unknown";
			const verdict = (action: Action, reasons: Reason[], reply: Reply, retryAfter?: number): Verdict => {
				record({ at: new Date(now()).toISOString(), endpoint: name, form, action, reasons });
				if (action !== "accept") log(`[emdash-nospam] ${name} form=${form} ${action} ${reasons.join(",")} ip=${tag}`);
				return { action, reply, reasons, ...(retryAfter ? { retryAfter } : {}), data };
			};
			const refuse = (reason: Reason) => verdict("reject", [reason], SILENT.has(reason) ? "silent" : "retry");

			// 1. Honeypot, then user agent: bots, answered as if it had worked.
			const trap = body[honeypotField];
			if (typeof trap === "string" ? trap.trim() : trap) return refuse("honeypot");
			const agent = agentOf(request);
			if (agents !== false && (!agent || agents.test(agent))) return refuse("user-agent");

			// 2. Token: genuine, for this form and browser, neither too young nor too old.
			const token = verifyToken(key, body[tokenField], form, bindAgent ? agentDigest(agent) : "");
			if (!token.ok) return refuse(token.reason);
			const age = (now() - token.issuedAt) / 1000;
			if (age < minSeconds) return refuse("too-fast");
			if (age > maxAgeSeconds) return refuse("token-expired");

			// 3. Rate limit, counted only for submissions that passed the bot checks (a shared address is not used
			//    up by bots), per IP pseudonym; unknown IPs share one larger bucket.
			if (limit) {
				const count = await store.hit(ip ? `${name}:${ipKey(key, ip)}` : `${name}:unknown`, limit.windowSeconds, now());
				if (count > (ip ? limit.max : limit.unknownMax)) return verdict("reject", ["rate-limit"], "limit", limit.windowSeconds);
			}

			// 4. Content.
			const keys = checkOptions.fields ?? Object.keys(data);
			const values = keys.map((k) => data[k]).filter((v): v is string => typeof v === "string" && v.trim() !== "");
			const found = inspect(values, rules);
			if (found.reject.length) return verdict("reject", found.reject, "silent");
			if (found.flag.length) return verdict("flag", found.flag, "ok");
			return verdict("accept", [], "ok");
		},
	};
}
