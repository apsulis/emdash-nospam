import { createHash, createHmac, hkdfSync, randomBytes, timingSafeEqual } from "node:crypto";

export type SecretSource = "option" | "NOSPAM_SECRET" | "EMDASH_ENCRYPTION_KEY" | "random";

const PREFIX = "n1";
const SIG_BYTES = 16;
const MIN_SECRET = 16;

/**
 * Signing key, derived with HKDF-SHA-256 so that the source secret itself never signs anything: the `secret`
 * option, else NOSPAM_SECRET, else EMDASH_ENCRYPTION_KEY (always set on an EmDash server), else a random key
 * that lives as long as the process (tokens then die with a restart).
 */
export function resolveSecret(option?: string): { key: Buffer; source: SecretSource } {
	const candidates: Array<[SecretSource, string | undefined]> = [
		["option", option],
		["NOSPAM_SECRET", process.env.NOSPAM_SECRET],
		["EMDASH_ENCRYPTION_KEY", process.env.EMDASH_ENCRYPTION_KEY],
	];
	for (const [source, value] of candidates) {
		const secret = value?.trim();
		if (!secret) continue;
		if (secret.length < MIN_SECRET) throw new Error(`emdash-nospam: ${source} is too short (${MIN_SECRET} characters minimum)`);
		return { key: Buffer.from(hkdfSync("sha256", secret, Buffer.alloc(0), "emdash-nospam/v1", 32)), source };
	}
	return { key: randomBytes(32), source: "random" };
}

/** Short digest of the user agent the token is bound to (empty string: not bound). */
export const agentDigest = (userAgent: string) => (userAgent ? createHash("sha256").update(userAgent).digest("base64url").slice(0, 16) : "");

function sign(key: Buffer, form: string, issuedAt: string, nonce: string, agent: string): Buffer {
	return createHmac("sha256", key).update(`${PREFIX}\n${form}\n${issuedAt}\n${nonce}\n${agent}`).digest().subarray(0, SIG_BYTES);
}

/** Token `n1.<issued at, base 36 ms>.<nonce>.<signature>`, bound to the form and, optionally, the user agent. */
export function issueToken(key: Buffer, form: string, agent: string, now: number): string {
	const issuedAt = now.toString(36);
	const nonce = randomBytes(9).toString("base64url");
	return [PREFIX, issuedAt, nonce, sign(key, form, issuedAt, nonce, agent).toString("base64url")].join(".");
}

export type TokenCheck = { ok: true; issuedAt: number } | { ok: false; reason: "token-missing" | "token-invalid" };

export function verifyToken(key: Buffer, token: unknown, form: string, agent: string): TokenCheck {
	if (typeof token !== "string" || !token) return { ok: false, reason: "token-missing" };
	const parts = token.length <= 200 ? token.split(".") : [];
	if (parts.length !== 4 || parts[0] !== PREFIX) return { ok: false, reason: "token-invalid" };
	const [, issuedAt, nonce, signature] = parts as [string, string, string, string];
	const expected = sign(key, form, issuedAt, nonce, agent);
	const given = Buffer.from(signature, "base64url");
	if (given.length !== expected.length || !timingSafeEqual(given, expected)) return { ok: false, reason: "token-invalid" };
	const at = Number.parseInt(issuedAt, 36);
	return Number.isSafeInteger(at) ? { ok: true, issuedAt: at } : { ok: false, reason: "token-invalid" };
}

/** Pseudonymous key for an IP (rate limit, logs): never the IP itself. */
export const ipKey = (key: Buffer, ip: string) => createHmac("sha256", key).update(`ip\n${ip}`).digest("base64url").slice(0, 22);
