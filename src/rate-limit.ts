/** Where submissions are counted. Implement it over Redis, a database… when several processes serve the site. */
export interface RateLimitStore {
	/** Counts one hit for `key` in its current window (opened by the first hit) and returns the count so far. */
	hit(key: string, windowSeconds: number, now: number): number | Promise<number>;
}

const SWEEP_MS = 60_000;
const MAX_KEYS = 100_000;

/**
 * In-process counters, enough for one Node process: EmDash on SQLite runs a single one. Counters reset with the
 * process; past MAX_KEYS live windows (a flood from rotating addresses) they are dropped rather than grow.
 */
export class MemoryStore implements RateLimitStore {
	readonly #windows = new Map<string, { count: number; resetAt: number }>();
	#sweptAt = 0;

	hit(key: string, windowSeconds: number, now: number): number {
		this.#sweep(now);
		const current = this.#windows.get(key);
		if (current && current.resetAt > now) return ++current.count;
		this.#windows.set(key, { count: 1, resetAt: now + windowSeconds * 1000 });
		return 1;
	}

	get size(): number {
		return this.#windows.size;
	}

	#sweep(now: number): void {
		if (now - this.#sweptAt < SWEEP_MS && this.#windows.size < MAX_KEYS) return;
		this.#sweptAt = now;
		for (const [key, window] of this.#windows) if (window.resetAt <= now) this.#windows.delete(key);
		if (this.#windows.size >= MAX_KEYS) this.#windows.clear();
	}
}
