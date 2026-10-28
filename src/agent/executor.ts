import { prisma } from '../db/client.js';
import { ToolRegistry, ToolContext } from '../tools/registry.js';
import { PolicyEngine } from '../policy/authorize.js';
import { logger, createTaskLogger } from '../observability/logger.js';
import { 
  Task, 
  Plan, 
  PlanStep, 
  TaskStep, 
  Operation, 
  StepType, 
  StepStatus, 
  RiskLevel,
  OperationType,
  OperationStatus,
  TaskStatus 
} from './task-state-machine.js';
import { TaskStateMachine } from './task-state-machine.js';

export interface ExecutionResult {
  success: boolean;
  completedSteps: number;
  failedSteps: number;
  results: Map<number, any>;
  errors: Map<number, string>;
}

export class Executor {
  private toolRegistry: ToolRegistry;
  private policyEngine: PolicyEngine;

  constructor(toolRegistry: ToolRegistry, policyEngine: PolicyEngine) {
    this.toolRegistry = toolRegistry;
    this.policyEngine = policyEngine;
  }

  async executePlan(
    task: Task,
    plan: Plan,
    context: ToolContext
  ): Promise<ExecutionResult> {
    const taskLogger = createTaskLogger(task.id);
    const results = new Map<number, any>();
    const errors = new Map<number, string>();
    let completedSteps = 0;
    let failedSteps = 0;

    taskLogger.info({ target: 'agent.executor', stepCount: plan.steps.length }, 'Starting plan execution');

    // Create task steps in database
    await this.createTaskSteps(task.id, plan.steps);

    for (const planStep of plan.steps) {
      // Check if task was cancelled
      const currentTask = await prisma.task.findUnique({ where: { id: task.id } });
      if (currentTask?.status === TaskStatus.CANCELLED) {
        taskLogger.warn({ target: 'agent.executor' }, 'Task cancelled during execution');
        break;
      }

      // Check dependencies
      const depsMet = await this.checkDependencies(task.id, planStep);
      if (!depsMet) {
        await this.updateTaskStep(task.id, planStep.stepIndex, StepStatus.BLOCKED, { 
          error: 'Dependencies not met' 
        });
        errors.set(planStep.stepIndex, 'Dependencies not met');
        failedSteps++;
        continue;
      }

      // Execute step
      try {
        taskLogger.info({ 
          target: 'agent.executor', 
          stepIndex: planStep.stepIndex,
          type: planStep.type,
          tool: planStep.toolName,
        }, 'Executing step');

        await this.updateTaskStep(task.id, planStep.stepIndex, StepStatus.RUNNING, { 
          startedAt: new Date() 
        });

        const result = await this.executeStep(task, planStep, context, results);
        
        await this.updateTaskStep(task.id, planStep.stepIndex, StepStatus.COMPLETED, {
          result,
          completedAt: new Date(),
          durationMs: Date.now() - (await this.getStepStartTime(task.id, planStep.stepIndex)),
          verified: false,
        });

        results.set(planStep.stepIndex, result);
        completedSteps++;

        taskLogger.info({ 
          target: 'agent.executor', 
          stepIndex: planStep.stepIndex 
        }, 'Step completed');
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        taskLogger.error({ 
          err: error, 
          target: 'agent.executor', 
          stepIndex: planStep.stepIndex 
        }, 'Step failed');

        await this.updateTaskStep(task.id, planStep.stepIndex, StepStatus.FAILED, {
          error: errorMessage,
          completedAt: new Date(),
        });

        errors.set(planStep.stepIndex, errorMessage);
        failedSteps++;

        // Check if we should continue or stop
        if (this.shouldStopOnFailure(planStep)) {
          taskLogger.warn({ target: 'agent.executor' }, 'Stopping execution due to critical failure');
          break;
        }
      }
    }

    return { success: failedSteps === 0, completedSteps, failedSteps, results, errors };
  }

  private async executeStep(
    task: Task,
    planStep: PlanStep,
    context: ToolContext,
    previousResults: Map<number, any>
  ): Promise<any> {
    const { type, toolName, toolArgs, readOnly } = planStep;

    switch (type) {
      case StepType.OBSERVATION:
        return this.executeObservation(task, planStep, context, previousResults);
      
      case StepType.MUTATION:
        return this.executeMutation(task, planStep, context, previousResults);
      
      case StepType.CONFIRMATION:
        return this.executeConfirmation(task, planStep, context);
      
      case StepType.CLARIFICATION:
        return this.executeClarification(task, planStep, context);
      
      case StepType.SUMMARY:
        return this.executeSummary(task, planStep, context, previousResults);
      
      default:
        throw new Error(`Unknown step type: ${type}`);
    }
  }

  private async executeObservation(
    task: Task,
    planStep: PlanStep,
    context: ToolContext,
    previousResults: Map<number, any>
  ): Promise<any> {
    if (!planStep.toolName) {
      throw new Error('Observation step requires a tool');
    }

    // Resolve tool arguments with previous results
    const resolvedArgs = this.resolveArguments(planStep.toolArgs, previousResults);
    
    // Validate input
    const validation = this.toolRegistry.validateInput(planStep.toolName, resolvedArgs);
    if (!validation.success) {
      throw new Error(`Invalid arguments: ${validation.error?.message}`);
    }

    // Check authorization
    const authResult = await this.policyEngine.authorize({
      guildId: context.guildId,
      userId: context.userId,
      toolName: planStep.toolName,
      toolArgs: validation.data,
      riskLevel: planStep.riskLevel,
      discordClient: context.discordClient,
      readOnly: planStep.readOnly,
    });

    if (!authResult.allowed) {
      throw new Error(`Authorization denied: ${authResult.reason}`);
    }

    // Create operation record
    const operation = await this.createOperation({
      taskId: task.id,
      stepIndex: planStep.stepIndex,
      type: OperationType.READ,
      toolName: planStep.toolName,
      toolArgs: validation.data,
      riskLevel: planStep.riskLevel,
      userId: context.userId,
      guildId: context.guildId,
    });

    try {
      // Execute tool
      const tool = this.toolRegistry.get(planStep.toolName)!;
      const toolContext: ToolContext = {
        ...context,
        taskId: task.id,
        operationId: operation.id,
      };

      const result = await tool.handler(validation.data, toolContext);

      // Validate output
      const outputValidation = this.toolRegistry.validateOutput(planStep.toolName, result);
      if (!outputValidation.success) {
        throw new Error(`Invalid output: ${outputValidation.error?.message}`);
      }

      // Update operation
      await this.updateOperation(operation.id, OperationStatus.SUCCEEDED, {
        result: outputValidation.data,
      });

      return outputValidation.data;
    } catch (error) {
      await this.updateOperation(operation.id, OperationStatus.FAILED, {
        error: error instanceof Error ? error.message : String(error),
      });
      throw error;
    }
  }

  private async executeMutation(
    task: Task,
    planStep: PlanStep,
    context: ToolContext,
    previousResults: Map<number, any>
  ): Promise<any> {
    if (!planStep.toolName) {
      throw new Error('Mutation step requires a tool');
    }

    // Resolve tool arguments
    const resolvedArgs = this.resolveArguments(planStep.toolArgs, previousResults);
    
    // Validate input
    const validation = this.toolRegistry.validateInput(planStep.toolName, resolvedArgs);
    if (!validation.success) {
      throw new Error(`Invalid arguments: ${validation.error?.message}`);
    }

    // Check authorization
    const authResult = await this.policyEngine.authorize({
      guildId: context.guildId,
      userId: context.userId,
      toolName: planStep.toolName,
      toolArgs: validation.data,
      riskLevel: planStep.riskLevel,
      discordClient: context.discordClient,
      readOnly: planStep.readOnly,
    });

    if (!authResult.allowed) {
      throw new Error(`Authorization denied: ${authResult.reason}`);
    }

    // Check if confirmation required
    if (authResult.requiresConfirmation && !planStep.toolArgs?.confirmed) {
      throw new Error('Confirmation required but not provided');
    }

    // Create operation record
    const operation = await this.createOperation({
      taskId: task.id,
      stepIndex: planStep.stepIndex,
      type: OperationType.MUTATION,
      toolName: planStep.toolName,
      toolArgs: validation.data,
      riskLevel: planStep.riskLevel,
      userId: context.userId,
      guildId: context.guildId,
      requiresConfirmation: authResult.requiresConfirmation,
      confirmationId: authResult.confirmationId,
    });

    try {
      // Update operation status
      await this.updateOperation(operation.id, OperationStatus.STARTED, { startedAt: new Date() });

      // Execute tool
      const tool = this.toolRegistry.get(planStep.toolName)!;
      const toolContext: ToolContext = {
        ...context,
        taskId: task.id,
        operationId: operation.id,
      };

      const result = await tool.handler(validation.data, toolContext);

      // Validate output
      const outputValidation = this.toolRegistry.validateOutput(planStep.toolName, result);
      if (!outputValidation.success) {
        throw new Error(`Invalid output: ${outputValidation.error?.message}`);
      }

      // Update operation
      await this.updateOperation(operation.id, OperationStatus.SUCCEEDED, {
        result: outputValidation.data,
      });

      return outputValidation.data;
    } catch (error) {
      await this.updateOperation(operation.id, OperationStatus.FAILED, {
        error: error instanceof Error ? error.message : String(error),
      });
      throw error;
    }
  }

  private async executeConfirmation(
    task: Task,
    planStep: PlanStep,
    context: ToolContext
  ): Promise<any> {
    // This step waits for user confirmation
    // The actual confirmation is handled via Discord interaction
    // Here we just record that confirmation is needed
    return { 
      requiresConfirmation: true,
      message: planStep.description,
      planStepIndex: planStep.stepIndex,
    };
  }

  private async executeClarification(
    task: Task,
    planStep: PlanStep,
    context: ToolContext
  ): Promise<any> {
    // This step asks user for clarification
    return {
      requiresClarification: true,
      question: planStep.description,
      planStepIndex: planStep.stepIndex,
    };
  }

  private async executeSummary(
    task: Task,
    planStep: PlanStep,
    context: ToolContext,
    previousResults: Map<number, any>
  ): Promise<any> {
    // Generate summary from all previous results
    const summary = this.generateSummary(previousResults, planStep.description);
    return { summary };
  }

  private resolveArguments(args: Record<string, any> | undefined, previousResults: Map<number, any>): Record<string, any> {
    if (!args) return {};
    
    const resolved: Record<string, any> = {};
    const argString = JSON.stringify(args);
    
    // Simple template replacement: {{step.N.field}} -> previousResults[N]?.field
    const replaced = argString.replace(/\{\{step\.(\d+)\.([^}]+)\}\}/g, (match, stepIndex, field) => {
      const stepResult = previousResults.get(parseInt(stepIndex, 10));
      if (stepResult && field in stepResult) {
        return JSON.stringify(stepResult[field]);
      }
      return match;
    });

    try {
      return JSON.parse(replaced);
    } catch {
      return args;
    }
  }

  private generateSummary(results: Map<number, any>, description: string): string {
    const parts: string[] = [description];
    
    for (const [index, result] of results) {
      if (result && typeof result === 'object') {
        parts.push(`Step ${index}: ${JSON.stringify(result).slice(0, 200)}`);
      }
    }
    
    return parts.join('\n');
  }

  private shouldStopOnFailure(planStep: PlanStep): boolean {
    return planStep.riskLevel === RiskLevel.CRITICAL || planStep.riskLevel === RiskLevel.HIGH;
  }

  private async checkDependencies(taskId: string, planStep: PlanStep): Promise<boolean> {
    for (const depIndex of planStep.dependsOn) {
      const depStep = await prisma.taskStep.findFirst({
        where: { taskId, stepIndex: depIndex },
      });
      if (!depStep || depStep.status !== StepStatus.COMPLETED) {
        return false;
      }
    }
    return true;
  }

  private async getStepStartTime(taskId: string, stepIndex: number): Promise<number> {
    const step = await prisma.taskStep.findFirst({
      where: { taskId, stepIndex },
      select: { startedAt: true },
    });
    return step?.startedAt?.getTime() ?? Date.now();
  }

  private async createTaskSteps(taskId: string, steps: PlanStep[]): Promise<void> {
    const data = steps.map(step => ({
      taskId,
      stepIndex: step.stepIndex,
      type: step.type,
      toolName: step.toolName,
      toolArgs: step.toolArgs as any,
      description: step.description,
      expectedOutput: step.expectedOutput,
      riskLevel: step.riskLevel,
      readOnly: step.readOnly,
      dependsOn: step.dependsOn,
      status: StepStatus.PENDING,
    }));

    await prisma.taskStep.createMany({ data: data as any, skipDuplicates: true });
  }

  private async updateTaskStep(
    taskId: string, 
    stepIndex: number, 
    status: StepStatus, 
    data: Partial<TaskStep> & Record<string, any>
  ): Promise<void> {
    await prisma.taskStep.update({
      where: { taskId_stepIndex: { taskId, stepIndex } },
      data: { status, ...data } as any,
    });
  }

  private async createOperation(params: {
    taskId: string;
    stepIndex: number;
    type: OperationType;
    toolName: string;
    toolArgs: Record<string, any>;
    riskLevel: RiskLevel;
    userId: string;
    guildId: string;
    requiresConfirmation?: boolean;
    confirmationId?: string;
  }): Promise<any> {
    const step = await prisma.taskStep.findFirst({
      where: { taskId: params.taskId, stepIndex: params.stepIndex },
    });

    return prisma.operation.create({
      data: {
        guildId: params.guildId,
        taskId: params.taskId,
        stepId: step?.id,
        userId: params.userId,
        type: params.type,
        toolName: params.toolName,
        toolArgs: params.toolArgs as any,
        riskLevel: params.riskLevel,
        requiresConfirmation: params.requiresConfirmation ?? false,
        confirmationId: params.confirmationId,
        status: OperationStatus.PLANNED,
        idempotencyKey: `${params.taskId}:${params.stepIndex}:${params.toolName}`,
      },
    });
  }

  private async updateOperation(
    operationId: string, 
    status: OperationStatus, 
    data: Partial<Operation> & Record<string, any>
  ): Promise<void> {
    await prisma.operation.update({
      where: { id: operationId },
      data: { status, ...data } as any,
    });
  }
}