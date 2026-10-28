import { prisma } from '../db/client.js';
import { logger, createGuildLogger } from '../observability/logger.js';
import { DiscordErrorClass, classifyDiscordError } from '../discord/rest-errors.js';
import { hierarchyManager } from './hierarchy.js';

export interface AuthorizationContext {
  guildId: string;
  userId: string;
  toolName: string;
  toolArgs: Record<string, any>;
  riskLevel: 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  discordClient?: any;
  readOnly?: boolean;
}

export interface AuthorizationResult {
  allowed: boolean;
  reason?: string;
  requiresConfirmation: boolean;
  confirmationId?: string;
  confirmationExpires?: Date;
  requiredPermissions?: string[];
  missingPermissions?: string[];
}

export interface ConfirmationRecord {
  id: string;
  guildId: string;
  userId: string;
  planId: string;
  planHash: string;
  toolName: string;
  toolArgs: Record<string, any>;
  riskLevel: string;
  expiresAt: Date;
  createdAt: Date;
  confirmedAt?: Date;
  confirmedBy?: string;
  deniedAt?: Date;
  deniedBy?: string;
}

export class PolicyEngine {
  private confirmationCache = new Map<string, ConfirmationRecord>();

  async authorize(context: AuthorizationContext): Promise<AuthorizationResult> {
    const guildLogger = createGuildLogger(context.guildId);

    try {
      // Get guild config
      const guildConfig = await prisma.guildConfig.findUnique({
        where: { guildId: context.guildId },
      });

      if (!guildConfig) {
        return { allowed: false, reason: 'Guild not configured', requiresConfirmation: false };
      }

      // Check if user is bot owner (global admin)
      const isBotOwner = await this.isBotOwner(context.userId);
      if (isBotOwner) {
        return { allowed: true, requiresConfirmation: false };
      }

      // Check guild-level permissions
      const memberPerms = await this.getMemberPermissions(context.guildId, context.userId);
      
      // Check if user has admin role
      const isAdmin = this.hasAdminRole(memberPerms.roles, guildConfig);
      const isModerator = this.hasModeratorRole(memberPerms.roles, guildConfig);
      const isTrustedStaff = this.hasTrustedStaffRole(memberPerms.roles, guildConfig);

      // Get tool-specific requirements
      const toolRequirements = this.getToolRequirements(context.toolName);
      
      // Check required Discord permissions
      const permissionCheck = await this.checkDiscordPermissions(
        context.guildId,
        context.userId,
        toolRequirements.requiredPermissions
      );

      if (!permissionCheck.hasAll) {
        return {
          allowed: false,
          reason: `Missing required permissions: ${permissionCheck.missing.join(', ')}`,
          requiresConfirmation: false,
          requiredPermissions: toolRequirements.requiredPermissions,
          missingPermissions: permissionCheck.missing,
        };
      }

      // Check role hierarchy for target (if applicable). Read-only lookups never
      // mutate anything, so a lower-ranked member can still look up a higher one.
      if (!context.readOnly) {
        const hierarchyCheck = await this.checkHierarchy(
          context.guildId,
          context.userId,
          context.toolArgs,
          context.discordClient
        );

        if (!hierarchyCheck.allowed) {
          return { allowed: false, reason: hierarchyCheck.reason, requiresConfirmation: false };
        }
      }

      // Check protected entities
      const protectedCheck = this.checkProtectedEntities(context.toolArgs, guildConfig);
      if (!protectedCheck.allowed) {
        return { allowed: false, reason: protectedCheck.reason, requiresConfirmation: false };
      }

      // Determine if confirmation required
      const requiresConfirmation = this.requiresConfirmation(
        context.riskLevel,
        context.toolName,
        isAdmin,
        isModerator,
        isTrustedStaff,
        guildConfig
      );

      let confirmationId: string | undefined;
      let confirmationExpires: Date | undefined;

      if (requiresConfirmation) {
        confirmationId = `confirm_${context.guildId}_${context.userId}_${Date.now()}`;
        confirmationExpires = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes
        
        // Store confirmation record
        await this.storeConfirmation({
          id: confirmationId,
          guildId: context.guildId,
          userId: context.userId,
          planId: '', // Will be set by caller
          planHash: '', // Will be set by caller
          toolName: context.toolName,
          toolArgs: context.toolArgs,
          riskLevel: context.riskLevel,
          expiresAt: confirmationExpires,
          createdAt: new Date(),
        });
      }

      guildLogger.debug({ 
        target: 'policy.authorize', 
        userId: context.userId,
        toolName: context.toolName,
        allowed: true,
        requiresConfirmation,
        isAdmin,
        isModerator,
        isTrustedStaff,
      }, 'Authorization check complete');

      return {
        allowed: true,
        requiresConfirmation,
        confirmationId,
        confirmationExpires,
      };
    } catch (error) {
      guildLogger.error({ err: error, target: 'policy.authorize' }, 'Authorization error');
      return { allowed: false, reason: 'Authorization check failed', requiresConfirmation: false };
    }
  }

  private async isBotOwner(userId: string): Promise<boolean> {
    // Check against environment variable or database
    const ownerId = process.env.BOT_OWNER_ID;
    return ownerId === userId;
  }

  private async getMemberPermissions(guildId: string, userId: string): Promise<{
    roles: string[];
    permissions: string;
    isOwner: boolean;
  }> {
    // This would typically fetch from Discord API
    // For now, return mock data - in reality this comes from the Discord client
    return { roles: [], permissions: '', isOwner: false };
  }

  private hasAdminRole(userRoles: string[], guildConfig: any): boolean {
    const adminRoles = guildConfig.adminRoles ?? [];
    return userRoles.some(r => adminRoles.includes(r));
  }

  private hasModeratorRole(userRoles: string[], guildConfig: any): boolean {
    const moderatorRoles = guildConfig.moderatorRoles ?? [];
    return userRoles.some(r => moderatorRoles.includes(r));
  }

  private hasTrustedStaffRole(userRoles: string[], guildConfig: any): boolean {
    const trustedRoles = guildConfig.trustedStaffRoles ?? [];
    return userRoles.some(r => trustedRoles.includes(r));
  }

  private getToolRequirements(toolName: string): { requiredPermissions: string[] } {
    // Define required permissions per tool
    const requirements: Record<string, string[]> = {
      // Moderation tools
      timeoutMember: ['ModerateMembers'],
      removeTimeout: ['ModerateMembers'],
      kickMember: ['KickMembers'],
      banMember: ['BanMembers'],
      unbanMember: ['BanMembers'],
      addRole: ['ManageRoles'],
      removeRole: ['ManageRoles'],
      setNickname: ['ManageNicknames'],
      deleteMessages: ['ManageMessages'],
      purgeMessages: ['ManageMessages'],
      setSlowmode: ['ManageChannels'],
      lockChannel: ['ManageChannels'],
      unlockChannel: ['ManageChannels'],
      createModerationCase: ['ModerateMembers'],

      // Server design tools
      createChannel: ['ManageChannels'],
      editChannel: ['ManageChannels'],
      deleteChannel: ['ManageChannels'],
      createCategory: ['ManageChannels'],
      editCategory: ['ManageChannels'],
      deleteCategory: ['ManageChannels'],
      moveChannel: ['ManageChannels'],
      proposeServerLayout: ['ManageChannels', 'ManageRoles'],
      applyServerLayout: ['ManageChannels', 'ManageRoles'],

      // Ticket tools
      createTicket: ['ManageChannels'],
      claimTicket: [],
      transferTicket: [],
      closeTicket: ['ManageChannels'],
      reopenTicket: ['ManageChannels'],

      // Application tools
      createApplicationPanel: ['ManageChannels', 'ManageRoles'],
      submitApplication: [],
      reviewApplication: [],
      decideApplication: [],

      // Staff tools
      setStaffDuty: [],
      getStaffActivity: [],
      createReport: ['ModerateMembers'],
      scheduleReminder: [],

      // Read-only tools (no special permissions needed)
      getGuildInfo: [],
      getMemberInfo: [],
      getChannelInfo: [],
      getRoleInfo: [],
      searchMembers: [],
      getAuditLog: ['ViewAuditLog'],
      getBotPermissions: [],
      comparePermissions: [],
    };

    return { requiredPermissions: requirements[toolName] ?? requirements[toolName.split('.').pop() ?? toolName] ?? [] };
  }

  private async checkDiscordPermissions(
    guildId: string,
    userId: string,
    requiredPermissions: string[]
  ): Promise<{ hasAll: boolean; hasAny: boolean; missing: string[] }> {
    // In reality, this would check the member's permissions in Discord
    // For now, we'll return a mock - the actual check happens in the tool handler
    // using the Discord.js member.permissions
    
    if (requiredPermissions.length === 0) {
      return { hasAll: true, hasAny: true, missing: [] };
    }

    // This is a placeholder - actual implementation needs Discord client
    return { hasAll: true, hasAny: true, missing: [] };
  }

  private async checkHierarchy(
    guildId: string,
    userId: string,
    toolArgs: Record<string, any>,
    discordClient: any
  ): Promise<{ allowed: boolean; reason?: string }> {
    // Check if target user/role is above the user or bot in hierarchy
    const targetUserId = toolArgs.userId;
    const targetRoleId = toolArgs.roleId;

    if (!targetUserId && !targetRoleId) {
      return { allowed: true };
    }

    if (!discordClient) {
      // Fail closed: without a Discord client we cannot verify role positions,
      // and skipping the check would let a lower-ranked member act on a higher one.
      return { allowed: false, reason: 'Hierarchy check unavailable: no Discord client' };
    }

    const targetType: 'USER' | 'ROLE' = targetUserId ? 'USER' : 'ROLE';
    const targetId = targetUserId ?? targetRoleId;

    const result = await hierarchyManager.checkHierarchy(guildId, userId, targetId, targetType, discordClient);
    return { allowed: result.allowed, reason: result.reason };
  }

  private checkProtectedEntities(
    toolArgs: Record<string, any>,
    guildConfig: any
  ): { allowed: boolean; reason?: string } {
    const protectedRoles = guildConfig.protectedRoles ?? [];
    const protectedChannels = guildConfig.protectedChannels ?? [];
    const protectedCategories = guildConfig.protectedCategories ?? [];

    // Check if targeting protected role
    if (toolArgs.roleId && protectedRoles.includes(toolArgs.roleId)) {
      return { allowed: false, reason: 'Cannot modify protected role' };
    }

    // Check if targeting protected channel
    if (toolArgs.channelId && protectedChannels.includes(toolArgs.channelId)) {
      return { allowed: false, reason: 'Cannot modify protected channel' };
    }

    // Check if targeting protected category
    if (toolArgs.categoryId && protectedCategories.includes(toolArgs.categoryId)) {
      return { allowed: false, reason: 'Cannot modify protected category' };
    }

    return { allowed: true };
  }

  private requiresConfirmation(
    riskLevel: string,
    toolName: string,
    isAdmin: boolean,
    isModerator: boolean,
    isTrustedStaff: boolean,
    guildConfig: any
  ): boolean {
    // Always require confirmation for critical risk
    if (riskLevel === 'CRITICAL') return true;
    
    // Require confirmation for high risk unless admin
    if (riskLevel === 'HIGH' && !isAdmin) return true;
    
    // Require confirmation for medium risk unless moderator or admin
    if (riskLevel === 'MEDIUM' && !isAdmin && !isModerator) return true;

    // Check tool-specific confirmation requirements
    const alwaysConfirm = [
      'banMember',
      'deleteChannel',
      'deleteCategory',
      'purgeMessages',
      'applyServerLayout',
    ];

    if (alwaysConfirm.includes(toolName) || alwaysConfirm.includes(toolName.split('.').pop() ?? toolName)) return true;

    return false;
  }

  private async storeConfirmation(record: ConfirmationRecord): Promise<void> {
    this.confirmationCache.set(record.id, record);
    
    // Also persist to database
    // await prisma.confirmation.create({ data: record });
  }

  async validateConfirmation(
    confirmationId: string,
    userId: string,
    planHash: string
  ): Promise<{ valid: boolean; record?: ConfirmationRecord; reason?: string }> {
    const record = this.confirmationCache.get(confirmationId);
    
    if (!record) {
      // Try database
      // record = await prisma.confirmation.findUnique({ where: { id: confirmationId } });
    }

    if (!record) {
      return { valid: false, reason: 'Confirmation not found' };
    }

    if (record.userId !== userId) {
      return { valid: false, reason: 'Confirmation belongs to different user' };
    }

    if (record.expiresAt < new Date()) {
      return { valid: false, reason: 'Confirmation expired' };
    }

    if (record.planHash !== planHash) {
      return { valid: false, reason: 'Plan changed since confirmation' };
    }

    if (record.confirmedAt || record.deniedAt) {
      return { valid: false, reason: 'Confirmation already used' };
    }

    return { valid: true, record };
  }

  async confirmAction(
    confirmationId: string,
    userId: string
  ): Promise<{ success: boolean; record?: ConfirmationRecord }> {
    const record = this.confirmationCache.get(confirmationId);
    
    if (!record) {
      return { success: false };
    }

    record.confirmedAt = new Date();
    record.confirmedBy = userId;
    this.confirmationCache.set(confirmationId, record);

    return { success: true, record };
  }

  async denyConfirmation(
    confirmationId: string,
    userId: string
  ): Promise<{ success: boolean }> {
    const record = this.confirmationCache.get(confirmationId);
    
    if (!record) {
      return { success: false };
    }

    record.deniedAt = new Date();
    record.deniedBy = userId;
    this.confirmationCache.set(confirmationId, record);

    return { success: true };
  }

  cleanupExpiredConfirmations(): void {
    const now = new Date();
    for (const [id, record] of this.confirmationCache.entries()) {
      if (record.expiresAt < now) {
        this.confirmationCache.delete(id);
      }
    }
  }
}

export const policyEngine = new PolicyEngine();