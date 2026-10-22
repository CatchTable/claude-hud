import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as net from 'net';
import * as tls from 'tls';
import * as https from 'https';
import { execFileSync } from 'child_process';
import { createHash } from 'crypto';
import type { StdinData, UsageData as BaseUsageData } from './types.js';
import { createDebug } from './debug.js';
import { getClaudeConfigDir, getHudPluginDir } from './claude-config-dir.js';

// CatchTable fork: Enterprise accounts get no stdin rate_limits, so usage falls back to the OAuth usage API.
// Extra fields stay local to this file to keep the upstream types untouched.
type StdinRateLimits = NonNullable<StdinData['rate_limits']>;
export type UsageData = BaseUsageData & {
  apiUnavailable?: boolean; // true if OAuth API call failed
  apiError?: string; // short error reason (e.g., rate-limited, timeout, 401)
};

const debug = createDebug('usage');
const LEGACY_KEYCHAIN_SERVICE_NAME = 'Claude Code-credentials';

interface CredentialsFile {
  claudeAiOauth?: {
    accessToken?: string;
    refreshToken?: string;
    subscriptionType?: string;
    rateLimitTier?: string;
    expiresAt?: number;
    scopes?: string[];
  };
}

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

const CACHE_TTL_MS = 5 * 60_000;
const CACHE_FAILURE_TTL_MS = 15_000;
const CACHE_RATE_LIMITED_BASE_MS = 60_000;
const CACHE_RATE_LIMITED_MAX_MS = 5 * 60_000;
const CACHE_LOCK_STALE_MS = 30_000;
const CACHE_LOCK_WAIT_MS = 2_000;
const CACHE_LOCK_POLL_MS = 50;
const KEYCHAIN_TIMEOUT_MS = 3000;
const KEYCHAIN_BACKOFF_MS = 60_000;
const USAGE_API_TIMEOUT_MS_DEFAULT = 15_000;
export const USAGE_API_USER_AGENT = 'claude-code/2.1';

const ALLOWED_PROXY_PATTERNS = ['wadcorp', 'catchtable'];

function isUsingCustomApiEndpoint(env: NodeJS.ProcessEnv = process.env): boolean {
  const baseUrl = env.ANTHROPIC_BASE_URL?.trim() || env.ANTHROPIC_API_BASE_URL?.trim();
  if (!baseUrl) return false;
  try {
    return new URL(baseUrl).origin !== 'https://api.anthropic.com';
  } catch {
    return true;
  }
}

interface CacheFile {
  data: UsageData;
  timestamp: number;
  rateLimitedCount?: number;
  retryAfterUntil?: number;
  lastGoodData?: UsageData;
}

interface CacheState {
  data: UsageData;
  timestamp: number;
  isFresh: boolean;
}

type CacheLockStatus = 'acquired' | 'busy' | 'unsupported';

// Per-account file suffix: profiles that share plugins/ via symlink (claude-account) must not share usage state.
// Default ~/.claude keeps the legacy file names.
function getAccountFileSuffix(homeDir: string): string {
  const serviceName = getKeychainServiceName(getClaudeConfigDir(homeDir), homeDir);
  return serviceName.slice(LEGACY_KEYCHAIN_SERVICE_NAME.length);
}

function getCachePath(homeDir: string): string {
  return path.join(getHudPluginDir(homeDir), `.usage-cache${getAccountFileSuffix(homeDir)}.json`);
}

function getCacheLockPath(homeDir: string): string {
  return path.join(getHudPluginDir(homeDir), `.usage-cache${getAccountFileSuffix(homeDir)}.lock`);
}

function hydrateCacheData(data: UsageData): UsageData {
  if (data.fiveHourResetAt) {
    data.fiveHourResetAt = new Date(data.fiveHourResetAt);
  }
  if (data.sevenDayResetAt) {
    data.sevenDayResetAt = new Date(data.sevenDayResetAt);
  }
  return data;
}

type CacheTtls = { cacheTtlMs: number; failureCacheTtlMs: number };

function getRateLimitedTtlMs(count: number): number {
  return Math.min(CACHE_RATE_LIMITED_BASE_MS * Math.pow(2, Math.max(0, count - 1)), CACHE_RATE_LIMITED_MAX_MS);
}

function getRateLimitedRetryUntil(cache: CacheFile): number | null {
  if (cache.data.apiError !== 'rate-limited') return null;
  if (cache.retryAfterUntil && cache.retryAfterUntil > cache.timestamp) return cache.retryAfterUntil;
  if (cache.rateLimitedCount && cache.rateLimitedCount > 0) {
    return cache.timestamp + getRateLimitedTtlMs(cache.rateLimitedCount);
  }
  return null;
}

function withRateLimitedSyncing(data: UsageData): UsageData {
  return { ...data, apiError: 'rate-limited' };
}

function readCacheState(homeDir: string, now: number, ttls: CacheTtls): CacheState | null {
  try {
    const cachePath = getCachePath(homeDir);
    if (!fs.existsSync(cachePath)) return null;

    const content = fs.readFileSync(cachePath, 'utf8');
    const cache: CacheFile = JSON.parse(content);

    const displayData = (cache.data.apiError === 'rate-limited' && cache.lastGoodData)
      ? withRateLimitedSyncing(cache.lastGoodData)
      : cache.data;

    const rateLimitedRetryUntil = getRateLimitedRetryUntil(cache);
    if (rateLimitedRetryUntil && now < rateLimitedRetryUntil) {
      return { data: hydrateCacheData(displayData), timestamp: cache.timestamp, isFresh: true };
    }

    const ttl = cache.data.apiUnavailable ? ttls.failureCacheTtlMs : ttls.cacheTtlMs;
    return {
      data: hydrateCacheData(displayData),
      timestamp: cache.timestamp,
      isFresh: now - cache.timestamp < ttl,
    };
  } catch {
    return null;
  }
}

function readRateLimitedCount(homeDir: string): number {
  try {
    const cachePath = getCachePath(homeDir);
    if (!fs.existsSync(cachePath)) return 0;
    const content = fs.readFileSync(cachePath, 'utf8');
    const cache: CacheFile = JSON.parse(content);
    return cache.rateLimitedCount ?? 0;
  } catch {
    return 0;
  }
}

function readLastGoodData(homeDir: string): UsageData | null {
  try {
    const cachePath = getCachePath(homeDir);
    if (!fs.existsSync(cachePath)) return null;
    const content = fs.readFileSync(cachePath, 'utf8');
    const cache: CacheFile = JSON.parse(content);
    return cache.lastGoodData ? hydrateCacheData(cache.lastGoodData) : null;
  } catch {
    return null;
  }
}

function readCache(homeDir: string, now: number, ttls: CacheTtls): UsageData | null {
  const cache = readCacheState(homeDir, now, ttls);
  return cache?.isFresh ? cache.data : null;
}

interface WriteCacheOpts {
  rateLimitedCount?: number;
  retryAfterUntil?: number;
  lastGoodData?: UsageData;
}

function writeCache(homeDir: string, data: UsageData, timestamp: number, opts?: WriteCacheOpts): void {
  try {
    const cachePath = getCachePath(homeDir);
    const cacheDir = path.dirname(cachePath);
    if (!fs.existsSync(cacheDir)) {
      fs.mkdirSync(cacheDir, { recursive: true });
    }
    const cache: CacheFile = { data, timestamp };
    if (opts?.rateLimitedCount && opts.rateLimitedCount > 0) cache.rateLimitedCount = opts.rateLimitedCount;
    if (opts?.retryAfterUntil) cache.retryAfterUntil = opts.retryAfterUntil;
    if (opts?.lastGoodData) cache.lastGoodData = opts.lastGoodData;
    fs.writeFileSync(cachePath, JSON.stringify(cache), 'utf8');
  } catch {
    // Ignore cache write failures
  }
}

function readLockTimestamp(lockPath: string): number | null {
  try {
    if (!fs.existsSync(lockPath)) return null;
    const raw = fs.readFileSync(lockPath, 'utf8').trim();
    const parsed = Number.parseInt(raw, 10);
    return Number.isFinite(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function tryAcquireCacheLock(homeDir: string): CacheLockStatus {
  const lockPath = getCacheLockPath(homeDir);
  const cacheDir = path.dirname(lockPath);

  try {
    if (!fs.existsSync(cacheDir)) {
      fs.mkdirSync(cacheDir, { recursive: true });
    }
    const fd = fs.openSync(lockPath, 'wx');
    try {
      fs.writeFileSync(fd, String(Date.now()), 'utf8');
    } finally {
      fs.closeSync(fd);
    }
    return 'acquired';
  } catch (error) {
    const maybeError = error as NodeJS.ErrnoException;
    if (maybeError.code !== 'EEXIST') {
      debug('Usage cache lock unavailable:', maybeError.message);
      return 'unsupported';
    }
  }

  const lockTimestamp = readLockTimestamp(lockPath);
  if (lockTimestamp === null) {
    try {
      const lockStat = fs.statSync(lockPath);
      if (Date.now() - lockStat.mtimeMs < CACHE_LOCK_STALE_MS) return 'busy';
    } catch {
      return tryAcquireCacheLock(homeDir);
    }
    try { fs.unlinkSync(lockPath); } catch { return 'busy'; }
    return tryAcquireCacheLock(homeDir);
  }

  if (lockTimestamp != null && Date.now() - lockTimestamp > CACHE_LOCK_STALE_MS) {
    try { fs.unlinkSync(lockPath); } catch { return 'busy'; }
    return tryAcquireCacheLock(homeDir);
  }

  return 'busy';
}

function releaseCacheLock(homeDir: string): void {
  try {
    const lockPath = getCacheLockPath(homeDir);
    if (fs.existsSync(lockPath)) fs.unlinkSync(lockPath);
  } catch {
    // Ignore
  }
}

async function waitForFreshCache(
  homeDir: string,
  now: () => number,
  ttls: CacheTtls,
  timeoutMs: number = CACHE_LOCK_WAIT_MS,
): Promise<UsageData | null> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, CACHE_LOCK_POLL_MS));
    const cached = readCache(homeDir, now(), ttls);
    if (cached) return cached;
    if (!fs.existsSync(getCacheLockPath(homeDir))) break;
  }
  return readCache(homeDir, now(), ttls);
}

// Dependency injection for testing
export type UsageApiDeps = {
  homeDir: () => string;
  fetchApi: (accessToken: string) => Promise<UsageApiResult>;
  now: () => number;
  readKeychain: (now: number, homeDir: string) => { accessToken: string; subscriptionType: string } | null;
  ttls: CacheTtls;
  stdinRateLimits?: StdinRateLimits;
};

const defaultDeps: UsageApiDeps = {
  homeDir: () => os.homedir(),
  fetchApi: fetchUsageApi,
  now: () => Date.now(),
  readKeychain: readKeychainCredentials,
  ttls: { cacheTtlMs: CACHE_TTL_MS, failureCacheTtlMs: CACHE_FAILURE_TTL_MS },
};

/**
 * Get usage data. Prefers stdin rate_limits when available (Pro/Max plans on CC v2.1.80+).
 * Falls back to OAuth API for Enterprise/older CC versions where stdin rate_limits are absent.
 */
export async function getUsage(overrides: Partial<UsageApiDeps> = {}): Promise<UsageData | null> {
  const deps = { ...defaultDeps, ...overrides };
  const now = deps.now();
  const homeDir = deps.homeDir();

  // Prefer official rate_limits from Claude Code stdin (v2.1.80+)
  if (deps.stdinRateLimits) {
    const rl = deps.stdinRateLimits;
    const fiveHour = parseRateLimitPercent(rl.five_hour?.used_percentage);
    const sevenDay = parseRateLimitPercent(rl.seven_day?.used_percentage);
    if (fiveHour !== null || sevenDay !== null) {
      debug('Using official stdin rate_limits');
      return {
        fiveHour,
        sevenDay,
        fiveHourResetAt: parseRateLimitResetAt(rl.five_hour?.resets_at),
        sevenDayResetAt: parseRateLimitResetAt(rl.seven_day?.resets_at),
      };
    }
  }

  // Skip usage API if user is using a custom provider (unless it's a company proxy)
  if (isUsingCustomApiEndpoint()) {
    const baseUrl = (process.env.ANTHROPIC_BASE_URL ?? process.env.ANTHROPIC_API_BASE_URL ?? '').trim();
    const isCompanyProxy = ALLOWED_PROXY_PATTERNS.some((p) => baseUrl.includes(p));
    if (!isCompanyProxy) {
      debug('Skipping usage API: custom API endpoint configured');
      return null;
    }
    debug('Custom endpoint is company proxy — attempting usage API');
  }

  // Check file-based cache
  const cacheState = readCacheState(homeDir, now, deps.ttls);
  if (cacheState?.isFresh) return cacheState.data;

  let holdsCacheLock = false;
  const lockStatus = tryAcquireCacheLock(homeDir);
  if (lockStatus === 'busy') {
    if (cacheState) return cacheState.data;
    return await waitForFreshCache(homeDir, deps.now, deps.ttls);
  }
  holdsCacheLock = lockStatus === 'acquired';

  try {
    const refreshedCache = readCache(homeDir, deps.now(), deps.ttls);
    if (refreshedCache) return refreshedCache;

    const credentials = readCredentials(homeDir, now, deps.readKeychain);
    if (!credentials) return null;

    const { accessToken } = credentials;

    const apiResult = await deps.fetchApi(accessToken);
    if (!apiResult.data) {
      const isRateLimited = apiResult.error === 'rate-limited';
      const prevCount = readRateLimitedCount(homeDir);
      const rateLimitedCount = isRateLimited ? prevCount + 1 : 0;
      const retryAfterUntil =
        isRateLimited && apiResult.retryAfterSec ? now + apiResult.retryAfterSec * 1000 : undefined;
      const backoffOpts: WriteCacheOpts = {
        rateLimitedCount: isRateLimited ? rateLimitedCount : undefined,
        retryAfterUntil,
      };

      const failureResult: UsageData = {
        fiveHour: null,
        sevenDay: null,
        fiveHourResetAt: null,
        sevenDayResetAt: null,
        apiUnavailable: true,
        apiError: apiResult.error,
      };

      if (isRateLimited) {
        const staleCache = readCacheState(homeDir, now, deps.ttls);
        const lastGood = readLastGoodData(homeDir);
        const goodData = staleCache && !staleCache.data.apiUnavailable ? staleCache.data : lastGood;
        if (goodData) {
          writeCache(homeDir, failureResult, now, { ...backoffOpts, lastGoodData: goodData });
          return withRateLimitedSyncing(goodData);
        }
      }

      writeCache(homeDir, failureResult, now, backoffOpts);
      return failureResult;
    }

    const fiveHour = parseUtilization(apiResult.data.five_hour?.utilization);
    const sevenDay = parseUtilization(apiResult.data.seven_day?.utilization);
    const fiveHourResetAt = parseDate(apiResult.data.five_hour?.resets_at);
    const sevenDayResetAt = parseDate(apiResult.data.seven_day?.resets_at);

    const result: UsageData = { fiveHour, sevenDay, fiveHourResetAt, sevenDayResetAt };
    writeCache(homeDir, result, now, { lastGoodData: result });
    return result;
  } catch (error) {
    debug('getUsage failed:', error);
    return null;
  } finally {
    if (holdsCacheLock) releaseCacheLock(homeDir);
  }
}

// --- Stdin rate_limits parsing (matches upstream getUsageFromStdin logic) ---

function parseRateLimitPercent(value: number | null | undefined): number | null {
  if (value == null) return null;
  if (!Number.isFinite(value)) return null;
  return Math.round(Math.max(0, Math.min(100, value)));
}

function parseRateLimitResetAt(value: number | null | undefined): Date | null {
  if (value == null) return null;
  const date = value > 1e12 ? new Date(value) : new Date(value * 1000);
  return isNaN(date.getTime()) ? null : date;
}

// --- Keychain & Credentials ---

function getKeychainBackoffPath(homeDir: string): string {
  return path.join(getHudPluginDir(homeDir), `.keychain-backoff${getAccountFileSuffix(homeDir)}`);
}

function isKeychainBackoff(homeDir: string, now: number): boolean {
  try {
    const backoffPath = getKeychainBackoffPath(homeDir);
    if (!fs.existsSync(backoffPath)) return false;
    const timestamp = parseInt(fs.readFileSync(backoffPath, 'utf8'), 10);
    return now - timestamp < KEYCHAIN_BACKOFF_MS;
  } catch {
    return false;
  }
}

function recordKeychainFailure(homeDir: string, now: number): void {
  try {
    const backoffPath = getKeychainBackoffPath(homeDir);
    const dir = path.dirname(backoffPath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(backoffPath, String(now), 'utf8');
  } catch {
    // Ignore
  }
}

export function getKeychainServiceName(configDir: string, homeDir: string): string {
  const normalizedConfigDir = path.normalize(path.resolve(configDir));
  const normalizedDefaultDir = path.normalize(path.resolve(path.join(homeDir, '.claude')));
  if (normalizedConfigDir === normalizedDefaultDir) return LEGACY_KEYCHAIN_SERVICE_NAME;
  const hash = createHash('sha256').update(normalizedConfigDir).digest('hex').slice(0, 8);
  return `${LEGACY_KEYCHAIN_SERVICE_NAME}-${hash}`;
}

export function getKeychainServiceNames(
  configDir: string,
  homeDir: string,
  env: NodeJS.ProcessEnv = process.env,
): string[] {
  const serviceNames: string[] = [getKeychainServiceName(configDir, homeDir)];
  const envConfigDir = env.CLAUDE_CONFIG_DIR?.trim();
  if (envConfigDir) {
    const normalizedDefaultDir = path.normalize(path.resolve(path.join(homeDir, '.claude')));
    const normalizedEnvDir = path.normalize(path.resolve(envConfigDir));
    if (normalizedEnvDir === normalizedDefaultDir) {
      serviceNames.push(LEGACY_KEYCHAIN_SERVICE_NAME);
    } else {
      const envHash = createHash('sha256').update(envConfigDir).digest('hex').slice(0, 8);
      serviceNames.push(`${LEGACY_KEYCHAIN_SERVICE_NAME}-${envHash}`);
    }
  }
  serviceNames.push(LEGACY_KEYCHAIN_SERVICE_NAME);
  return [...new Set(serviceNames)];
}

function isMissingKeychainItemError(error: unknown): boolean {
  if (!error || typeof error !== 'object') return false;
  const maybeError = error as { status?: unknown; message?: unknown; stderr?: unknown };
  if (maybeError.status === 44) return true;
  const message = typeof maybeError.message === 'string' ? maybeError.message.toLowerCase() : '';
  if (message.includes('could not be found in the keychain')) return true;
  const stderr =
    typeof maybeError.stderr === 'string'
      ? maybeError.stderr.toLowerCase()
      : Buffer.isBuffer(maybeError.stderr)
        ? maybeError.stderr.toString('utf8').toLowerCase()
        : '';
  return stderr.includes('could not be found in the keychain');
}

export function resolveKeychainCredentials(
  serviceNames: string[],
  now: number,
  loadService: (serviceName: string, accountName?: string) => string,
  accountName?: string | null,
): { credentials: { accessToken: string; subscriptionType: string } | null; shouldBackoff: boolean } {
  let shouldBackoff = false;
  let allowGenericFallback = Boolean(accountName);

  for (const serviceName of serviceNames) {
    try {
      const keychainData = accountName ? loadService(serviceName, accountName) : loadService(serviceName);
      if (accountName) allowGenericFallback = false;
      const trimmedKeychainData = keychainData.trim();
      if (!trimmedKeychainData) continue;
      const data: CredentialsFile = JSON.parse(trimmedKeychainData);
      const credentials = parseCredentialsData(data, now);
      if (credentials) return { credentials, shouldBackoff: false };
    } catch (error) {
      if (!isMissingKeychainItemError(error)) {
        if (accountName) allowGenericFallback = false;
        shouldBackoff = true;
      }
    }
  }

  if (!accountName || !allowGenericFallback) {
    return { credentials: null, shouldBackoff };
  }

  for (const serviceName of serviceNames) {
    try {
      const keychainData = loadService(serviceName).trim();
      if (!keychainData) continue;
      const data: CredentialsFile = JSON.parse(keychainData);
      const credentials = parseCredentialsData(data, now);
      if (credentials) return { credentials, shouldBackoff: false };
    } catch (error) {
      if (!isMissingKeychainItemError(error)) shouldBackoff = true;
    }
  }

  return { credentials: null, shouldBackoff };
}

function getKeychainAccountName(): string | null {
  try {
    const username = os.userInfo().username.trim();
    return username || null;
  } catch {
    return null;
  }
}

function readKeychainCredentials(
  now: number,
  homeDir: string,
): { accessToken: string; subscriptionType: string } | null {
  if (process.platform !== 'darwin') return null;
  if (isKeychainBackoff(homeDir, now)) {
    debug('Keychain in backoff period, skipping');
    return null;
  }

  try {
    const configDir = getClaudeConfigDir(homeDir);
    const serviceNames = getKeychainServiceNames(configDir, homeDir);
    const accountName = getKeychainAccountName();

    const resolved = resolveKeychainCredentials(
      serviceNames,
      now,
      (serviceName, lookupAccountName) =>
        execFileSync(
          '/usr/bin/security',
          lookupAccountName
            ? ['find-generic-password', '-s', serviceName, '-a', lookupAccountName, '-w']
            : ['find-generic-password', '-s', serviceName, '-w'],
          { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'], timeout: KEYCHAIN_TIMEOUT_MS },
        ),
      accountName,
    );

    if (resolved.credentials) return resolved.credentials;
    if (resolved.shouldBackoff) recordKeychainFailure(homeDir, now);
    return null;
  } catch (error) {
    const message = error instanceof Error ? error.message : 'unknown error';
    debug('Failed to read from macOS Keychain:', message);
    recordKeychainFailure(homeDir, now);
    return null;
  }
}

function readFileCredentials(
  homeDir: string,
  now: number,
): { accessToken: string; subscriptionType: string } | null {
  const credentialsPath = path.join(getClaudeConfigDir(homeDir), '.credentials.json');
  if (!fs.existsSync(credentialsPath)) return null;
  try {
    const content = fs.readFileSync(credentialsPath, 'utf8');
    const data: CredentialsFile = JSON.parse(content);
    return parseCredentialsData(data, now);
  } catch (error) {
    debug('Failed to read credentials file:', error);
    return null;
  }
}

function parseCredentialsData(
  data: CredentialsFile,
  now: number,
): { accessToken: string; subscriptionType: string } | null {
  const accessToken = data.claudeAiOauth?.accessToken;
  const subscriptionType = data.claudeAiOauth?.subscriptionType ?? '';
  if (!accessToken) return null;
  const expiresAt = data.claudeAiOauth?.expiresAt;
  if (expiresAt != null && expiresAt <= now) {
    debug('OAuth token expired');
    return null;
  }
  return { accessToken, subscriptionType };
}

function readCredentials(
  homeDir: string,
  now: number,
  readKeychain: (now: number, homeDir: string) => { accessToken: string; subscriptionType: string } | null,
): { accessToken: string; subscriptionType: string } | null {
  const keychainCreds = readKeychain(now, homeDir);
  if (keychainCreds) {
    debug('Using credentials from macOS Keychain');
    return keychainCreds;
  }
  const fileCreds = readFileCredentials(homeDir, now);
  if (fileCreds) {
    debug('Using credentials from file');
    return fileCreds;
  }
  return null;
}

function parseUtilization(value: number | undefined): number | null {
  if (value == null) return null;
  if (!Number.isFinite(value)) return null;
  return Math.round(Math.max(0, Math.min(100, value)));
}

function parseDate(dateStr: string | undefined): Date | null {
  if (!dateStr) return null;
  const date = new Date(dateStr);
  if (isNaN(date.getTime())) {
    debug('Invalid date string:', dateStr);
    return null;
  }
  return date;
}

export function getUsageApiTimeoutMs(env: NodeJS.ProcessEnv = process.env): number {
  const raw = env.CLAUDE_HUD_USAGE_TIMEOUT_MS?.trim();
  if (!raw) return USAGE_API_TIMEOUT_MS_DEFAULT;
  const parsed = Number(raw);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    debug('Invalid CLAUDE_HUD_USAGE_TIMEOUT_MS value:', raw);
    return USAGE_API_TIMEOUT_MS_DEFAULT;
  }
  return parsed;
}

export function isNoProxy(hostname: string, env: NodeJS.ProcessEnv = process.env): boolean {
  const noProxy = env.NO_PROXY ?? env.no_proxy;
  if (!noProxy) return false;
  const host = hostname.toLowerCase();
  return noProxy.split(',').some((entry) => {
    const pattern = entry.trim().toLowerCase();
    if (!pattern) return false;
    if (pattern === '*') return true;
    if (host === pattern) return true;
    const suffix = pattern.startsWith('.') ? pattern : `.${pattern}`;
    return host.endsWith(suffix);
  });
}

export function getProxyUrl(hostname: string, env: NodeJS.ProcessEnv = process.env): URL | null {
  if (isNoProxy(hostname, env)) {
    debug('Proxy bypassed by NO_PROXY for host:', hostname);
    return null;
  }
  const proxyEnv =
    env.HTTPS_PROXY ?? env.https_proxy ?? env.ALL_PROXY ?? env.all_proxy ?? env.HTTP_PROXY ?? env.http_proxy;
  if (!proxyEnv) return null;
  try {
    const proxyUrl = new URL(proxyEnv);
    if (proxyUrl.protocol !== 'http:' && proxyUrl.protocol !== 'https:') {
      debug('Unsupported proxy protocol:', proxyUrl.protocol);
      return null;
    }
    return proxyUrl;
  } catch {
    debug('Invalid proxy URL:', proxyEnv);
    return null;
  }
}

function createProxyTunnelAgent(proxyUrl: URL): https.Agent {
  const proxyHost = proxyUrl.hostname;
  const proxyPort = Number.parseInt(proxyUrl.port || (proxyUrl.protocol === 'https:' ? '443' : '80'), 10);
  const proxyAuth = proxyUrl.username
    ? `Basic ${Buffer.from(`${decodeURIComponent(proxyUrl.username)}:${decodeURIComponent(proxyUrl.password || '')}`).toString('base64')}`
    : null;

  return new (class extends https.Agent {
    override createConnection(
      options: https.RequestOptions,
      callback?: (err: Error | null, socket: net.Socket) => void,
    ): undefined {
      const targetHost = String(options.host ?? options.hostname ?? 'localhost');
      const targetPort = Number(options.port) || 443;

      let settled = false;
      const settle = (err: Error | null, socket: net.Socket): void => {
        if (settled) return;
        settled = true;
        callback?.(err, socket);
      };

      const proxySocket =
        proxyUrl.protocol === 'https:'
          ? tls.connect({ host: proxyHost, port: proxyPort, servername: proxyHost })
          : net.connect(proxyPort, proxyHost);

      proxySocket.once('error', (error) => settle(error, proxySocket));

      proxySocket.once('connect', () => {
        const connectHeaders = [`CONNECT ${targetHost}:${targetPort} HTTP/1.1`, `Host: ${targetHost}:${targetPort}`];
        if (proxyAuth) connectHeaders.push(`Proxy-Authorization: ${proxyAuth}`);
        connectHeaders.push('', '');
        proxySocket.write(connectHeaders.join('\r\n'));

        let responseBuffer = Buffer.alloc(0);
        const onData = (chunk: Buffer): void => {
          responseBuffer = Buffer.concat([responseBuffer, chunk]);
          const headerEndIndex = responseBuffer.indexOf('\r\n\r\n');
          if (headerEndIndex === -1) return;
          proxySocket.removeListener('data', onData);

          const headerText = responseBuffer.subarray(0, headerEndIndex).toString('utf8');
          const statusLine = headerText.split('\r\n')[0] ?? '';
          if (!/^HTTP\/1\.[01] 200 /.test(statusLine)) {
            const error = new Error(`Proxy CONNECT rejected: ${statusLine || 'unknown status'}`);
            proxySocket.destroy(error);
            settle(error, proxySocket);
            return;
          }

          const tlsSocket = tls.connect(
            {
              socket: proxySocket,
              servername: String(options.servername ?? targetHost),
              rejectUnauthorized: options.rejectUnauthorized !== false,
            },
            () => settle(null, tlsSocket),
          );
          tlsSocket.once('error', (error) => settle(error, tlsSocket));
        };

        proxySocket.on('data', onData);
      });

      return undefined;
    }
  })();
}

function fetchUsageApi(accessToken: string): Promise<UsageApiResult> {
  return new Promise((resolve) => {
    const host = 'api.anthropic.com';
    const timeoutMs = getUsageApiTimeoutMs();
    const proxyUrl = getProxyUrl(host);
    const options = {
      hostname: host,
      path: '/api/oauth/usage',
      method: 'GET',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'anthropic-beta': 'oauth-2025-04-20',
        'User-Agent': USAGE_API_USER_AGENT,
      },
      timeout: timeoutMs,
      agent: proxyUrl ? createProxyTunnelAgent(proxyUrl) : undefined,
    };

    if (proxyUrl) debug('Using proxy for usage API:', proxyUrl.origin);

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', (chunk: Buffer) => (data += chunk.toString()));
      res.on('end', () => {
        if (res.statusCode !== 200) {
          debug('API returned non-200 status:', res.statusCode);
          const error = res.statusCode === 429 ? 'rate-limited' : res.statusCode ? `http-${res.statusCode}` : 'http-error';
          const retryAfterSec = res.statusCode === 429 ? parseRetryAfterSeconds(res.headers['retry-after']) : undefined;
          resolve({ data: null, error, retryAfterSec });
          return;
        }
        try {
          const parsed: UsageApiResponse = JSON.parse(data);
          resolve({ data: parsed });
        } catch (error) {
          debug('Failed to parse API response:', error);
          resolve({ data: null, error: 'parse' });
        }
      });
    });

    req.on('error', (error) => {
      debug('API request error:', error);
      resolve({ data: null, error: 'network' });
    });
    req.on('timeout', () => {
      debug('API request timeout');
      req.destroy();
      resolve({ data: null, error: 'timeout' });
    });
    req.end();
  });
}

export function parseRetryAfterSeconds(raw: string | string[] | undefined, nowMs: number = Date.now()): number | undefined {
  const value = Array.isArray(raw) ? raw[0] : raw;
  if (!value) return undefined;
  const parsedSeconds = Number.parseInt(value, 10);
  if (Number.isFinite(parsedSeconds) && parsedSeconds > 0) return parsedSeconds;
  const retryAtMs = Date.parse(value);
  if (!Number.isFinite(retryAtMs)) return undefined;
  const retryAfterSeconds = Math.ceil((retryAtMs - nowMs) / 1000);
  return retryAfterSeconds > 0 ? retryAfterSeconds : undefined;
}

export function clearCache(homeDir?: string): void {
  if (homeDir) {
    try {
      const cachePath = getCachePath(homeDir);
      if (fs.existsSync(cachePath)) fs.unlinkSync(cachePath);
      const lockPath = getCacheLockPath(homeDir);
      if (fs.existsSync(lockPath)) fs.unlinkSync(lockPath);
    } catch {
      // Ignore
    }
  }
}
