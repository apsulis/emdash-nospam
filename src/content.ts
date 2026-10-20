/**
 * Content heuristics, after the SPIP « nospam » plugin (links counted per message, hidden markup), written anew.
 * Only plain-text form values are inspected; nothing is stored or logged.
 */

export type ContentReason = "links" | "bbcode" | "hidden-content" | "blocked-word" | "markup" | "link-in-short-field" | "script";

export interface ContentRules {
	/** Links in the whole message: flag from `flag`, reject from `reject`. */
	links: { flag: number; reject: number } | false;
	/** A link in a short one-line field (name, subject, phone…). */
	shortFieldLinks: "flag" | "reject" | "ignore";
	/** Normalised words (lower case, no accents): any of them rejects the message. */
	blockedWords: RegExp | null;
	/** Letters of these Unicode scripts expected; mostly others → flag. */
	allowedScripts: RegExp | null;
}

const URL_PATTERN = /\bhttps?:\/\/[^\s<>"'\]]+|\bwww\.[a-z0-9-]+\.[a-z]{2,}[^\s<>"'\]]*/gi;
const BBCODE = /\[\/?(?:url|link)\b/i;
const HIDDEN = /style\s*=\s*["']?[^"'>]*(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0(?![.\d]*[1-9]))/i;
const MARKUP = /<\s*(?:a\s[^>]*href|script|iframe|img\s)/i;
const LETTER = /\p{L}/gu;
const SHORT = 120;
const MIN_LETTERS = 20;

const normalise = (text: string) => text.normalize("NFKD").replace(/\p{M}/gu, "").toLowerCase();

/** Word list → one regular expression, whole words only, accents and case ignored. */
export function blockedWordsPattern(words: string[]): RegExp | null {
	const list = words.map((word) => normalise(word.trim())).filter(Boolean);
	if (!list.length) return null;
	const escaped = list.map((word) => word.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
	return new RegExp(`(?<![\\p{L}\\p{N}])(?:${escaped.join("|")})(?![\\p{L}\\p{N}])`, "u");
}

/** Unicode script names (Latin, Cyrillic, Han…) → one pattern; an unknown name throws. */
export function scriptsPattern(scripts: string[] | null | undefined): RegExp | null {
	if (!scripts?.length) return null;
	return new RegExp(scripts.map((script) => `\\p{Script=${script}}`).join("|"), "gu");
}

export function inspect(values: string[], rules: ContentRules): { reject: ContentReason[]; flag: ContentReason[] } {
	const reject = new Set<ContentReason>();
	const flag = new Set<ContentReason>();
	let links = 0;
	for (const value of values) {
		const count = value.match(URL_PATTERN)?.length ?? 0;
		links += count;
		if (count && !value.includes("\n") && value.length <= SHORT && rules.shortFieldLinks !== "ignore") {
			(rules.shortFieldLinks === "reject" ? reject : flag).add("link-in-short-field");
		}
		if (BBCODE.test(value)) reject.add("bbcode");
		if (HIDDEN.test(value)) reject.add("hidden-content");
		else if (MARKUP.test(value)) flag.add("markup");
		if (rules.blockedWords?.test(normalise(value))) reject.add("blocked-word");
	}
	if (rules.links) {
		if (links >= rules.links.reject) reject.add("links");
		else if (links >= rules.links.flag) flag.add("links");
	}
	if (rules.allowedScripts) {
		const text = values.join(" ");
		const letters = text.match(LETTER)?.length ?? 0;
		const expected = text.match(rules.allowedScripts)?.length ?? 0;
		if (letters >= MIN_LETTERS && expected / letters < 0.5) flag.add("script");
	}
	for (const reason of reject) flag.delete(reason);
	return { reject: [...reject], flag: [...flag] };
}
