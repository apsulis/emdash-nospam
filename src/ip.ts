import { isIP } from "node:net";

/** Headers that carry the client IP: the option, else EMDASH_TRUSTED_PROXY_HEADERS (the setting EmDash itself reads). */
export function trustedHeaders(option?: string[]): string[] {
	const names = option ?? (process.env.EMDASH_TRUSTED_PROXY_HEADERS ?? "").split(",");
	return names.map((name) => name.trim().toLowerCase()).filter(Boolean);
}

export interface ClientIp {
	/** Normalised IP (IPv6: its /64 network), or null when it cannot be trusted. */
	ip: string | null;
	/** An X-Forwarded-For header was present but is not trusted: the site is probably behind a proxy. */
	untrustedForward: boolean;
}

/**
 * Client IP, from the trusted headers first. For an X-Forwarded-For header, its LAST entry: the one your own proxy
 * appended (the earlier ones are whatever the client sent). Then the socket address, unless the request came
 * through a proxy that is not trusted: every visitor would then share the proxy's address.
 */
export function clientIp(request: Request, headers: string[], clientAddress?: string | null): ClientIp {
	for (const name of headers) {
		const value = request.headers.get(name);
		if (!value) continue;
		const candidate = name.endsWith("forwarded-for")
			? value
					.split(",")
					.map((entry) => entry.trim())
					.filter(Boolean)
					.at(-1)
			: value;
		const ip = normaliseIp(candidate);
		if (ip) return { ip, untrustedForward: false };
	}
	const untrustedForward = request.headers.has("x-forwarded-for") && !headers.includes("x-forwarded-for");
	return { ip: untrustedForward ? null : normaliseIp(clientAddress), untrustedForward };
}

/** Valid IP or null; IPv4-mapped IPv6 → IPv4; IPv6 → its /64 network (one subscriber usually holds a whole /64). */
export function normaliseIp(value?: string | null): string | null {
	if (!value) return null;
	let ip = value.trim().replace(/^\[(.*)\]$/, "$1").replace(/%.*$/, "");
	const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(ip);
	if (mapped) ip = mapped[1]!;
	const version = isIP(ip);
	if (version === 4) return ip;
	if (version !== 6) return null;
	return `${expandIpv6(ip).slice(0, 4).join(":")}::/64`;
}

function expandIpv6(ip: string): string[] {
	const groups = (part: string) => (part ? part.split(":").flatMap((g) => (g.includes(".") ? ["0", "0"] : [g])) : []);
	const [head = "", tail] = ip.split("::");
	const left = groups(head);
	const right = tail === undefined ? [] : groups(tail);
	const zeros = tail === undefined ? [] : new Array<string>(8 - left.length - right.length).fill("0");
	return [...left, ...zeros, ...right].map((g) => Number.parseInt(g, 16).toString(16));
}
