/**
 * Browser helper for forms that are rendered statically or on the client and post to another endpoint: get a
 * token from your endpoint's GET, send it with the form. No dependency, no Node API, a few hundred bytes.
 *
 *   let nospam = null;
 *   form.addEventListener("focusin", async () => (nospam ??= await fetchToken(endpoint)), { once: true });
 *   form.addEventListener("submit", async (event) => {
 *     event.preventDefault();
 *     nospam = await readyToken(nospam, endpoint);
 *     await fetch(endpoint, { method: "POST", headers: { "Content-Type": "application/json" },
 *       body: JSON.stringify(withToken(Object.fromEntries(new FormData(form)), nospam)) });
 *   });
 *
 * Render the honeypot too, left empty: an input named `nospam.honeypot` (default `website_url`) inside an element
 * styled with HONEYPOT_STYLE, with `tabindex="-1"`, `autocomplete="off"` and `aria-hidden="true"` on the wrapper.
 */

export interface NospamToken {
	token: string;
	field: string;
	honeypot: string;
	minSeconds: number;
	maxAgeSeconds: number;
	/** Date.now() when the token was received (the server clock is never compared with this one). */
	receivedAt: number;
}

/** Default name of the honeypot field, to render it before the first token arrives. */
export const HONEYPOT_FIELD = "website_url";

/** Off-screen rather than `display: none`, which some bots skip. */
export const HONEYPOT_STYLE = "position:absolute;left:-10000px;top:auto;width:1px;height:1px;overflow:hidden";

export async function fetchToken(url: string, init?: RequestInit): Promise<NospamToken> {
	const response = await fetch(url, { method: "GET", cache: "no-store", ...init });
	if (!response.ok) throw new Error(`nospam token: HTTP ${response.status}`);
	const json = (await response.json()) as Omit<NospamToken, "receivedAt">;
	if (typeof json?.token !== "string") throw new Error("nospam token: invalid answer");
	return { ...json, receivedAt: Date.now() };
}

/**
 * A token fit to be sent now: a missing or expiring one is replaced, and if it is younger than the minimum delay,
 * waits for the rest of it (a person who fills a form in less than a few seconds is rare; a bot that waits is slow).
 */
export async function readyToken(current: NospamToken | null | undefined, url: string, init?: RequestInit): Promise<NospamToken> {
	let token = current;
	if (!token || Date.now() - token.receivedAt > (token.maxAgeSeconds - 60) * 1000) token = await fetchToken(url, init);
	const wait = token.minSeconds * 1000 + 250 - (Date.now() - token.receivedAt);
	if (wait > 0) await new Promise((resolve) => setTimeout(resolve, wait));
	return token;
}

/** The body with the token added. */
export const withToken = <T extends Record<string, unknown>>(body: T, token: NospamToken) => ({ ...body, [token.field]: token.token });
