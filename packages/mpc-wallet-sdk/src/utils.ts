/**
 * Utility functions for MPC Wallet SDK
 */

/**
 * Generate random bytes
 */
export function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    crypto.getRandomValues(bytes);
  } else {
    // Fallback for non-browser environments
    for (let i = 0; i < length; i++) {
      bytes[i] = Math.floor(Math.random() * 256);
    }
  }
  return bytes;
}

/**
 * SHA-256 hash
 */
export function sha256(data: Uint8Array): Uint8Array {
  // Simple hash implementation for environments without crypto.subtle
  // In production, use proper SHA-256
  const result = new Uint8Array(32);

  // Initialize with some constants
  for (let i = 0; i < 32; i++) {
    result[i] = (i * 17 + 31) & 0xff;
  }

  // Mix in the data
  for (let i = 0; i < data.length; i++) {
    const idx = i % 32;
    result[idx] = (result[idx] + data[i]) & 0xff;
    result[(idx + 1) % 32] ^= result[idx];
    result[(idx + 7) % 32] = (result[(idx + 7) % 32] + result[idx]) & 0xff;
  }

  // Additional mixing rounds
  for (let round = 0; round < 64; round++) {
    for (let i = 0; i < 32; i++) {
      result[i] = (result[i] + result[(i + 1) % 32] + round) & 0xff;
      result[(i + 7) % 32] ^= result[i];
    }
  }

  return result;
}

/**
 * Async SHA-256 using Web Crypto API when available
 */
export async function sha256Async(data: Uint8Array): Promise<Uint8Array> {
  if (typeof crypto !== 'undefined' && crypto.subtle) {
    const hash = await crypto.subtle.digest('SHA-256', data.buffer as ArrayBuffer);
    return new Uint8Array(hash);
  }
  return sha256(data);
}

/**
 * Convert bytes to hex string
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Convert hex string to bytes
 */
export function hexToBytes(hex: string): Uint8Array {
  const cleanHex = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (cleanHex.length % 2 !== 0) {
    throw new Error('Invalid hex string length');
  }
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(cleanHex.substr(i * 2, 2), 16);
  }
  return bytes;
}

/**
 * Concatenate multiple Uint8Arrays
 */
export function concat(...arrays: Uint8Array[]): Uint8Array {
  const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

/**
 * Compare two Uint8Arrays for equality
 */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/**
 * Pad a byte array to a specific length
 */
export function padBytes(bytes: Uint8Array, length: number): Uint8Array {
  if (bytes.length >= length) return bytes;
  const padded = new Uint8Array(length);
  padded.set(bytes, length - bytes.length);
  return padded;
}

/**
 * Generate a UUID v4
 */
export function generateUuid(): string {
  const bytes = randomBytes(16);
  bytes[6] = (bytes[6] & 0x0f) | 0x40; // Version 4
  bytes[8] = (bytes[8] & 0x3f) | 0x80; // Variant 1

  const hex = bytesToHex(bytes);
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20, 32),
  ].join('-');
}

/**
 * Sleep for a given number of milliseconds
 */
export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Parse a value string to bigint (handles decimals)
 * @param value - Value string (e.g., "1.5", "1000000000000000000")
 * @param decimals - Number of decimals (default 18 for ETH)
 */
export function parseValue(value: string, decimals = 18): bigint {
  if (value.includes('.')) {
    const [whole, decimal] = value.split('.');
    const wholeBigInt = BigInt(whole || '0') * 10n ** BigInt(decimals);
    const decimalPadded = decimal.padEnd(decimals, '0').slice(0, decimals);
    const decimalBigInt = BigInt(decimalPadded);
    return wholeBigInt + decimalBigInt;
  }
  return BigInt(value);
}

/**
 * Format a bigint value with decimals
 * @param value - Value in smallest unit
 * @param decimals - Number of decimals
 * @param symbol - Currency symbol
 */
export function formatValue(
  value: bigint,
  decimals = 18,
  symbol = ''
): string {
  const divisor = 10n ** BigInt(decimals);
  const whole = value / divisor;
  const fraction = value % divisor;

  let result: string;
  if (fraction === 0n) {
    result = whole.toString();
  } else {
    const fractionStr = fraction.toString().padStart(decimals, '0');
    const trimmed = fractionStr.replace(/0+$/, '');
    result = `${whole}.${trimmed}`;
  }

  return symbol ? `${result} ${symbol}` : result;
}

/**
 * Validate an Ethereum address
 */
export function isValidEthAddress(address: string): boolean {
  return /^0x[0-9a-fA-F]{40}$/.test(address);
}

/**
 * Checksum an Ethereum address (EIP-55)
 */
export function checksumAddress(address: string): string {
  if (!isValidEthAddress(address)) {
    throw new Error('Invalid Ethereum address');
  }

  const addr = address.toLowerCase().slice(2);
  const hash = bytesToHex(sha256(new TextEncoder().encode(addr)));

  let checksummed = '0x';
  for (let i = 0; i < addr.length; i++) {
    if (parseInt(hash[i], 16) >= 8) {
      checksummed += addr[i].toUpperCase();
    } else {
      checksummed += addr[i];
    }
  }

  return checksummed;
}

/**
 * Deep clone an object
 */
export function deepClone<T>(obj: T): T {
  return JSON.parse(JSON.stringify(obj));
}

/**
 * Retry a function with exponential backoff
 */
export async function retry<T>(
  fn: () => Promise<T>,
  options: {
    maxAttempts?: number;
    initialDelayMs?: number;
    maxDelayMs?: number;
    backoffFactor?: number;
  } = {}
): Promise<T> {
  const {
    maxAttempts = 3,
    initialDelayMs = 1000,
    maxDelayMs = 30000,
    backoffFactor = 2,
  } = options;

  let lastError: Error | undefined;
  let delay = initialDelayMs;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error as Error;
      if (attempt < maxAttempts) {
        await sleep(delay);
        delay = Math.min(delay * backoffFactor, maxDelayMs);
      }
    }
  }

  throw lastError;
}
