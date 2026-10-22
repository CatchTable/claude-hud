import type { UsageData, StdinRateLimits } from './types.js';
export type { UsageData } from './types.js';
interface UsageApiResponse {
    five_hour?: {
        utilization?: number;
        resets_at?: string;
    };
    seven_day?: {
        utilization?: number;
        resets_at?: string;
    };
}
interface UsageApiResult {
    data: UsageApiResponse | null;
    error?: string;
    retryAfterSec?: number;
}
export declare const USAGE_API_USER_AGENT = "claude-code/2.1";
type CacheTtls = {
    cacheTtlMs: number;
    failureCacheTtlMs: number;
};
export type UsageApiDeps = {
    homeDir: () => string;
    fetchApi: (accessToken: string) => Promise<UsageApiResult>;
    now: () => number;
    readKeychain: (now: number, homeDir: string) => {
        accessToken: string;
        subscriptionType: string;
    } | null;
    ttls: CacheTtls;
    stdinRateLimits?: StdinRateLimits;
};
/**
 * Get usage data. Prefers stdin rate_limits when available (Pro/Max plans on CC v2.1.80+).
 * Falls back to OAuth API for Enterprise/older CC versions where stdin rate_limits are absent.
 */
export declare function getUsage(overrides?: Partial<UsageApiDeps>): Promise<UsageData | null>;
export declare function getKeychainServiceName(configDir: string, homeDir: string): string;
export declare function getKeychainServiceNames(configDir: string, homeDir: string, env?: NodeJS.ProcessEnv): string[];
export declare function resolveKeychainCredentials(serviceNames: string[], now: number, loadService: (serviceName: string, accountName?: string) => string, accountName?: string | null): {
    credentials: {
        accessToken: string;
        subscriptionType: string;
    } | null;
    shouldBackoff: boolean;
};
export declare function getUsageApiTimeoutMs(env?: NodeJS.ProcessEnv): number;
export declare function isNoProxy(hostname: string, env?: NodeJS.ProcessEnv): boolean;
export declare function getProxyUrl(hostname: string, env?: NodeJS.ProcessEnv): URL | null;
export declare function parseRetryAfterSeconds(raw: string | string[] | undefined, nowMs?: number): number | undefined;
export declare function clearCache(homeDir?: string): void;
//# sourceMappingURL=usage-api.d.ts.map