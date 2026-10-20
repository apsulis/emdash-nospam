import type { PluginDescriptor } from "emdash";

export const PLUGIN_ID = "nospam";
export const VERSION = "0.1.1";

/**
 * Descriptor for `emdash({ plugins: [emdashNospam()] })`: the « Anti-spam » dashboard widget. The checks run in
 * your form endpoints, through `createNospam()` (see README).
 */
export function emdashNospam(): PluginDescriptor {
	return {
		id: PLUGIN_ID,
		version: VERSION,
		format: "native",
		entrypoint: "@apsulis/emdash-nospam/plugin",
		capabilities: [],
		adminWidgets: [{ id: "status", title: "Anti-spam", size: "half" }],
	};
}

export default emdashNospam;

export { createNospam, MemoryStore, MESSAGES, messageFor } from "./server.js";
export type { CheckOptions, Nospam, NospamOptions, RateLimitStore, Reason, Reply, TokenResponse, Verdict } from "./server.js";
