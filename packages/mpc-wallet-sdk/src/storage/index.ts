/**
 * Storage module for key shares
 */

import type { KeyShare } from '../keygen';

/**
 * Storage interface for key shares
 */
export interface KeyShareStore {
  /** Store a key share */
  store(id: string, share: KeyShare, password: string): Promise<void>;
  /** Load a key share */
  load(id: string, password: string): Promise<KeyShare>;
  /** Delete a key share */
  delete(id: string): Promise<boolean>;
  /** Check if a share exists */
  exists(id: string): Promise<boolean>;
  /** List all share IDs */
  list(): Promise<string[]>;
}

/**
 * In-memory store for testing
 */
export class MemoryStore implements KeyShareStore {
  private shares: Map<string, { encrypted: string; salt: string }> = new Map();

  async store(id: string, share: KeyShare, password: string): Promise<void> {
    const salt = generateSalt();
    const encrypted = await encrypt(JSON.stringify(share), password, salt);
    this.shares.set(id, { encrypted, salt });
  }

  async load(id: string, password: string): Promise<KeyShare> {
    const stored = this.shares.get(id);
    if (!stored) {
      throw new Error(`Share not found: ${id}`);
    }
    const decrypted = await decrypt(stored.encrypted, password, stored.salt);
    return JSON.parse(decrypted) as KeyShare;
  }

  async delete(id: string): Promise<boolean> {
    return this.shares.delete(id);
  }

  async exists(id: string): Promise<boolean> {
    return this.shares.has(id);
  }

  async list(): Promise<string[]> {
    return Array.from(this.shares.keys());
  }

  /** Clear all shares */
  clear(): void {
    this.shares.clear();
  }
}

/**
 * Browser storage using localStorage
 */
export class BrowserStore implements KeyShareStore {
  private prefix: string;

  constructor(prefix = 'mpc-wallet') {
    this.prefix = prefix;
  }

  private key(id: string): string {
    return `${this.prefix}:share:${id}`;
  }

  async store(id: string, share: KeyShare, password: string): Promise<void> {
    if (typeof localStorage === 'undefined') {
      throw new Error('localStorage not available');
    }

    const salt = generateSalt();
    const encrypted = await encrypt(JSON.stringify(share), password, salt);
    localStorage.setItem(this.key(id), JSON.stringify({ encrypted, salt }));

    // Update index
    const index = this.getIndex();
    if (!index.includes(id)) {
      index.push(id);
      localStorage.setItem(`${this.prefix}:index`, JSON.stringify(index));
    }
  }

  async load(id: string, password: string): Promise<KeyShare> {
    if (typeof localStorage === 'undefined') {
      throw new Error('localStorage not available');
    }

    const data = localStorage.getItem(this.key(id));
    if (!data) {
      throw new Error(`Share not found: ${id}`);
    }

    const { encrypted, salt } = JSON.parse(data);
    const decrypted = await decrypt(encrypted, password, salt);
    return JSON.parse(decrypted) as KeyShare;
  }

  async delete(id: string): Promise<boolean> {
    if (typeof localStorage === 'undefined') {
      return false;
    }

    const existed = localStorage.getItem(this.key(id)) !== null;
    localStorage.removeItem(this.key(id));

    // Update index
    const index = this.getIndex().filter((i) => i !== id);
    localStorage.setItem(`${this.prefix}:index`, JSON.stringify(index));

    return existed;
  }

  async exists(id: string): Promise<boolean> {
    if (typeof localStorage === 'undefined') {
      return false;
    }
    return localStorage.getItem(this.key(id)) !== null;
  }

  async list(): Promise<string[]> {
    return this.getIndex();
  }

  private getIndex(): string[] {
    if (typeof localStorage === 'undefined') {
      return [];
    }
    const data = localStorage.getItem(`${this.prefix}:index`);
    return data ? JSON.parse(data) : [];
  }
}

/**
 * Node.js file system storage
 */
export class FileSystemStore implements KeyShareStore {
  private basePath: string;

  constructor(basePath: string) {
    this.basePath = basePath;
  }

  private filePath(id: string): string {
    // Sanitize ID to prevent path traversal
    const safeId = id.replace(/[/\\.~]/g, '_');
    return `${this.basePath}/${safeId}.share`;
  }

  async store(id: string, share: KeyShare, password: string): Promise<void> {
    const fs = await import('fs/promises');

    // Create directory if needed
    await fs.mkdir(this.basePath, { recursive: true });

    const salt = generateSalt();
    const encrypted = await encrypt(JSON.stringify(share), password, salt);
    await fs.writeFile(
      this.filePath(id),
      JSON.stringify({ encrypted, salt }),
      'utf-8'
    );

    // Set restrictive permissions on Unix
    if (process.platform !== 'win32') {
      await fs.chmod(this.filePath(id), 0o600);
    }
  }

  async load(id: string, password: string): Promise<KeyShare> {
    const fs = await import('fs/promises');

    const data = await fs.readFile(this.filePath(id), 'utf-8');
    const { encrypted, salt } = JSON.parse(data);
    const decrypted = await decrypt(encrypted, password, salt);
    return JSON.parse(decrypted) as KeyShare;
  }

  async delete(id: string): Promise<boolean> {
    const fs = await import('fs/promises');

    try {
      // Overwrite with zeros before deleting
      const stat = await fs.stat(this.filePath(id));
      await fs.writeFile(this.filePath(id), Buffer.alloc(stat.size, 0));
      await fs.unlink(this.filePath(id));
      return true;
    } catch {
      return false;
    }
  }

  async exists(id: string): Promise<boolean> {
    const fs = await import('fs/promises');

    try {
      await fs.access(this.filePath(id));
      return true;
    } catch {
      return false;
    }
  }

  async list(): Promise<string[]> {
    const fs = await import('fs/promises');

    try {
      const files = await fs.readdir(this.basePath);
      return files
        .filter((f) => f.endsWith('.share'))
        .map((f) => f.replace('.share', ''));
    } catch {
      return [];
    }
  }
}

// ============================================================================
// Encryption Helpers
// ============================================================================

function generateSalt(): string {
  const bytes = new Uint8Array(32);
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    crypto.getRandomValues(bytes);
  } else {
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = Math.floor(Math.random() * 256);
    }
  }
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

async function encrypt(
  data: string,
  password: string,
  salt: string
): Promise<string> {
  // Simple XOR encryption for demo
  // In production, use Web Crypto API
  const key = await deriveKey(password, salt);
  const dataBytes = new TextEncoder().encode(data);
  const encrypted = new Uint8Array(dataBytes.length);

  for (let i = 0; i < dataBytes.length; i++) {
    encrypted[i] = dataBytes[i] ^ key[i % key.length];
  }

  return btoa(String.fromCharCode(...encrypted));
}

async function decrypt(
  encrypted: string,
  password: string,
  salt: string
): Promise<string> {
  const key = await deriveKey(password, salt);
  const dataBytes = Uint8Array.from(atob(encrypted), (c) => c.charCodeAt(0));
  const decrypted = new Uint8Array(dataBytes.length);

  for (let i = 0; i < dataBytes.length; i++) {
    decrypted[i] = dataBytes[i] ^ key[i % key.length];
  }

  return new TextDecoder().decode(decrypted);
}

async function deriveKey(password: string, salt: string): Promise<Uint8Array> {
  // Simple key derivation for demo
  // In production, use PBKDF2 or Argon2
  const combined = password + salt;
  const encoder = new TextEncoder();
  const data = encoder.encode(combined);

  // Simple hash
  const key = new Uint8Array(32);
  for (let i = 0; i < data.length; i++) {
    key[i % 32] ^= data[i];
  }

  // Multiple rounds
  for (let round = 0; round < 1000; round++) {
    for (let i = 0; i < 32; i++) {
      key[i] = (key[i] + key[(i + 1) % 32] + round) & 0xff;
    }
  }

  return key;
}

/**
 * Create a backup of multiple shares
 */
export async function createBackup(
  shares: KeyShare[],
  password: string
): Promise<string> {
  const salt = generateSalt();
  const data = JSON.stringify(shares);
  const encrypted = await encrypt(data, password, salt);

  return JSON.stringify({
    version: 1,
    createdAt: Date.now(),
    shareCount: shares.length,
    salt,
    encrypted,
  });
}

/**
 * Restore shares from a backup
 */
export async function restoreBackup(
  backup: string,
  password: string
): Promise<KeyShare[]> {
  const { salt, encrypted } = JSON.parse(backup);
  const data = await decrypt(encrypted, password, salt);
  return JSON.parse(data) as KeyShare[];
}
