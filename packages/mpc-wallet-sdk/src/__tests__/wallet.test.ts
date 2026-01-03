import { describe, it, expect } from 'vitest';
import {
  MpcAgentWallet,
  PolicyConfig,
  PolicyEngine,
  KeygenSession,
  MemoryStore,
  MpcWalletError,
} from '../index';

describe('MpcAgentWallet', () => {
  it('should create a new wallet instance', async () => {
    const wallet = await MpcAgentWallet.create();
    expect(wallet).toBeDefined();
    expect(wallet.hasKeyShare()).toBe(false);
  });

  it('should create wallet with custom policy', async () => {
    const policy = PolicyConfig.create()
      .withPerTxLimit(BigInt('1000000000000000000'))
      .withDailyLimit(BigInt('10000000000000000000'));

    const wallet = await MpcAgentWallet.create({ policy });
    expect(wallet.getPolicy()).toBeDefined();
  });

  it('should throw when accessing address without key share', async () => {
    const wallet = await MpcAgentWallet.create();
    expect(() => wallet.getAddress()).toThrow(MpcWalletError);
  });

  it('should return wallet info', async () => {
    const wallet = await MpcAgentWallet.create({ role: 1 });
    const info = wallet.getInfo();
    expect(info.role).toBe(1);
    expect(info.address).toBeNull();
    expect(info.publicKey).toBeNull();
    expect(info.hasPolicy).toBe(false);
  });
});

describe('PolicyEngine', () => {
  it('should create a policy engine with PolicyConfig', () => {
    const config = PolicyConfig.create();
    const engine = new PolicyEngine(config);
    expect(engine).toBeDefined();
  });

  it('should approve transactions within limits', () => {
    const config = PolicyConfig.create()
      .withPerTxLimit(BigInt('2000000000000000000')); // 2 ETH
    const engine = new PolicyEngine(config);

    const decision = engine.evaluate({
      requestId: 'test-1',
      chain: 0, // EVM
      to: '0x1234567890123456789012345678901234567890',
      value: '1000000000000000000', // 1 ETH
      chainId: 1,
      timestamp: Date.now(),
    });

    expect(decision.approved).toBe(true);
  });

  it('should reject transactions exceeding per-transaction limit', () => {
    const config = PolicyConfig.create()
      .withPerTxLimit(BigInt('1000000000000000000')); // 1 ETH
    const engine = new PolicyEngine(config);

    const decision = engine.evaluate({
      requestId: 'test-2',
      chain: 0,
      to: '0x1234567890123456789012345678901234567890',
      value: '2000000000000000000', // 2 ETH
      chainId: 1,
      timestamp: Date.now(),
    });

    expect(decision.approved).toBe(false);
    expect(decision.reason).toContain('per-transaction limit');
  });

  it('should handle blacklisted addresses', () => {
    const config = PolicyConfig.create()
      .withBlacklist(['0xbad0000000000000000000000000000000000001']);
    const engine = new PolicyEngine(config);

    const decision = engine.evaluate({
      requestId: 'test-3',
      chain: 0,
      to: '0xbad0000000000000000000000000000000000001',
      value: '1000000000000000000',
      chainId: 1,
      timestamp: Date.now(),
    });

    expect(decision.approved).toBe(false);
    expect(decision.reason).toContain('blacklisted');
  });

  it('should approve when policy is disabled', () => {
    const config = PolicyConfig.disabled();
    const engine = new PolicyEngine(config);

    const decision = engine.evaluate({
      requestId: 'test-4',
      chain: 0,
      to: '0x1234567890123456789012345678901234567890',
      value: '999999999999999999999999', // Very large
      chainId: 1,
      timestamp: Date.now(),
    });

    expect(decision.approved).toBe(true);
  });
});

describe('KeygenSession', () => {
  // Generate a valid 32-byte session ID (hex)
  const generateSessionId = () => {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    return Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  };

  it('should create a keygen session', () => {
    const session = new KeygenSession({
      role: 0, // Agent role
      sessionId: generateSessionId(),
    });
    expect(session).toBeDefined();
  });

  it('should generate round 1 message', () => {
    const session = new KeygenSession({
      role: 0,
      sessionId: generateSessionId(),
    });

    const round1Msg = session.generateRound1();
    // The message structure may vary, so just check it exists
    expect(round1Msg).toBeDefined();
  });
});

describe('MemoryStore', () => {
  // Create a valid KeyShare object with all required properties
  const createTestShare = () => ({
    shareId: 'test-share',
    role: 0,
    publicKey: '0x04abcd',
    ethAddress: '0x1234567890123456789012345678901234567890',
    createdAt: Date.now(),
    partyId: 0,
    encryptedData: 'encrypted-share-data',
    chainCode: '0000000000000000000000000000000000000000000000000000000000000000',
    nonce: '000000000000000000000000',
    salt: '0000000000000000',
    version: 1,
  });

  it('should store and retrieve key shares', async () => {
    const store = new MemoryStore();
    const share = createTestShare();

    await store.store('test-id', share, 'password123');
    const loaded = await store.load('test-id', 'password123');

    expect(loaded.shareId).toBe(share.shareId);
    expect(loaded.publicKey).toBe(share.publicKey);
    expect(loaded.ethAddress).toBe(share.ethAddress);
  });

  it('should throw on wrong password', async () => {
    const store = new MemoryStore();
    const share = createTestShare();

    await store.store('test-id', share, 'password123');
    await expect(store.load('test-id', 'wrong-password')).rejects.toThrow();
  });

  it('should list stored shares', async () => {
    const store = new MemoryStore();
    const share = createTestShare();

    await store.store('share1', share, 'password');
    await store.store('share2', share, 'password');

    const ids = await store.list();
    expect(ids).toContain('share1');
    expect(ids).toContain('share2');
    expect(ids.length).toBe(2);
  });

  it('should delete shares', async () => {
    const store = new MemoryStore();
    const share = createTestShare();

    await store.store('test-id', share, 'password');
    expect(await store.exists('test-id')).toBe(true);

    const deleted = await store.delete('test-id');
    expect(deleted).toBe(true);
    expect(await store.exists('test-id')).toBe(false);
  });
});

describe('Utilities', () => {
  it('should hash messages', async () => {
    const wallet = await MpcAgentWallet.create();
    const message = new TextEncoder().encode('Hello, World!');
    const hash = wallet.hashMessage(message);
    expect(hash).toBeDefined();
    expect(hash.length).toBe(32);
  });

  it('should hash ETH messages with prefix', async () => {
    const wallet = await MpcAgentWallet.create();
    const ethHash = wallet.hashEthMessage('Hello, World!');
    expect(ethHash).toBeDefined();
    expect(ethHash.length).toBe(32);
  });
});
