import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../../src/db/client.js', () => ({
  prisma: {
    guildConfig: {
      findUnique: vi.fn().mockResolvedValue({
        guildId: '100000000000000001',
        adminRoles: [],
        moderatorRoles: [],
        trustedStaffRoles: [],
        protectedRoles: [],
        protectedChannels: [],
        protectedCategories: [],
      }),
    },
  },
}));

import { PolicyEngine } from '../../src/policy/authorize.js';
import { hierarchyManager } from '../../src/policy/hierarchy.js';

function makeDiscordClient(positions: { bot: number; actor: number; target: number; ownerId?: string }) {
  const guild = {
    ownerId: positions.ownerId ?? 'owner-id',
    members: {
      fetchMe: vi.fn().mockResolvedValue({ roles: { highest: { id: 'bot-role', name: 'BotRole', position: positions.bot } } }),
      fetch: vi.fn((userId: string) => {
        if (userId === 'actor-id') {
          return Promise.resolve({ id: 'actor-id', roles: { highest: { id: 'actor-role', name: 'ActorRole', position: positions.actor } } });
        }
        return Promise.resolve({ id: userId, user: { tag: 'target#0001' }, roles: { highest: { id: 'target-role', name: 'TargetRole', position: positions.target } } });
      }),
    },
  };
  return { guilds: { fetch: vi.fn().mockResolvedValue(guild) } };
}

describe('HierarchyManager.checkHierarchy', () => {
  it('denies when the bot is not above the target', async () => {
    const client = makeDiscordClient({ bot: 1, actor: 5, target: 3 });
    const result = await hierarchyManager.checkHierarchy('guild-1', 'actor-id', 'target-id', 'USER', client);
    expect(result.allowed).toBe(false);
    expect(result.reason).toMatch(/Bot's highest role/);
  });

  it('denies when the acting user is not above the target', async () => {
    const client = makeDiscordClient({ bot: 10, actor: 2, target: 3 });
    const result = await hierarchyManager.checkHierarchy('guild-1', 'actor-id', 'target-id', 'USER', client);
    expect(result.allowed).toBe(false);
    expect(result.reason).toMatch(/Your highest role/);
  });

  it('allows when both bot and user outrank the target', async () => {
    const client = makeDiscordClient({ bot: 10, actor: 5, target: 3 });
    const result = await hierarchyManager.checkHierarchy('guild-1', 'actor-id', 'target-id', 'USER', client);
    expect(result.allowed).toBe(true);
  });
});

describe('PolicyEngine authorization hierarchy enforcement', () => {
  let policyEngine: PolicyEngine;

  beforeEach(() => {
    policyEngine = new PolicyEngine();
    vi.stubEnv('BOT_OWNER_ID', 'nobody');
  });

  it('denies a mutation against a higher-ranked target', async () => {
    const discordClient = makeDiscordClient({ bot: 10, actor: 2, target: 3 });
    const result = await policyEngine.authorize({
      guildId: 'guild-1',
      userId: 'actor-id',
      toolName: 'kickMember',
      toolArgs: { userId: 'target-id' },
      riskLevel: 'MEDIUM',
      discordClient,
      readOnly: false,
    });

    expect(result.allowed).toBe(false);
    expect(result.reason).toMatch(/Your highest role/);
  });

  it('allows a mutation against a lower-ranked target', async () => {
    const discordClient = makeDiscordClient({ bot: 10, actor: 5, target: 3 });
    const result = await policyEngine.authorize({
      guildId: 'guild-1',
      userId: 'actor-id',
      toolName: 'kickMember',
      toolArgs: { userId: 'target-id' },
      riskLevel: 'MEDIUM',
      discordClient,
      readOnly: false,
    });

    expect(result.allowed).toBe(true);
  });

  it('fails closed when no Discord client is available to verify hierarchy', async () => {
    const result = await policyEngine.authorize({
      guildId: 'guild-1',
      userId: 'actor-id',
      toolName: 'kickMember',
      toolArgs: { userId: 'target-id' },
      riskLevel: 'MEDIUM',
      readOnly: false,
    });

    expect(result.allowed).toBe(false);
    expect(result.reason).toMatch(/Hierarchy check unavailable/);
  });

  it('skips the hierarchy check for read-only lookups', async () => {
    const result = await policyEngine.authorize({
      guildId: 'guild-1',
      userId: 'actor-id',
      toolName: 'getMemberInfo',
      toolArgs: { userId: 'target-id' },
      riskLevel: 'NONE',
      readOnly: true,
    });

    expect(result.allowed).toBe(true);
  });
});
