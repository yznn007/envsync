/**
 * Plan、差异、冲突与历史恢复的受限 application-service 端口。
 *
 * 所有 decoder 都采用白名单投影：原生返回的额外字段、正文、路径或任意诊断文本不会进入
 * Vue 页面或 Pinia。手动裁决文本只作为一次调用参数存在，不被本模块缓存。
 */

import {
  invokeDesktop,
  opaqueIdentifier,
  safeResourceIdentifier,
  type SafeDiagnostic,
} from './tauri-api'

type JsonRecord = Record<string, unknown>

const risks = new Set(['low', 'medium', 'high'])
const actionKinds = new Set(['create_file', 'replace_file', 'delete_file', 'update_managed_block'])
const diffKinds = new Set(['added', 'removed', 'modified'])
const diffPresentations = new Set([
  'secret',
  'text',
  'structured',
  'managed_block',
  'binary',
  'content_summary',
])
const conflictKinds = new Set([
  'text_overlap',
  'delete_modify',
  'structured_key',
  'binary_both',
  'incompatible_policy',
])
const conflictStates = new Set(['open', 'resolved', 'superseded'])
const resolutionChoices = new Set(['ours', 'theirs', 'manual', 'delete'])
const operationStates = new Set([
  'planned',
  'preflighted',
  'published',
  'applying',
  'verified',
  'completed',
  'published_not_converged',
  'aborted',
  'rolling_back',
  'rolled_back',
])
const actionStates = new Set(['pending', 'staged', 'applied', 'verified', 'failed', 'rolled_back'])
const rollbackCapabilities = new Set(['exact', 'compensating', 'none'])
const fileModes = new Set(['full_file', 'managed_block', 'structured_merge', 'generated_include'])
const structuredFormats = new Set(['json', 'yaml', 'toml', 'ini', 'git_config'])

export type SafePlanAction = {
  resource: string
  kind: string
  target: string
  risk: 'low' | 'medium' | 'high'
  backup: string
  rollback: string
  sensitive: boolean
}

export type SafePlanView = {
  id: string
  workspace: string
  device_id: string
  target_snapshot: string
  base_revision: number
  next_revision: number
  actions: SafePlanAction[]
  diagnostics: SafeDiagnostic[]
}

export type SafeDiffView = {
  resource: string
  kind: 'added' | 'removed' | 'modified'
  sensitive: boolean
  presentation: 'secret' | 'text' | 'structured' | 'managed_block' | 'binary' | 'content_summary'
  content_bytes: number | null
  preview_truncated: boolean
  before_digest: string | null
  after_digest: string | null
}

export type SafeDiffListView = { plan: string; diffs: SafeDiffView[] }

export type SafeConflictView = {
  id: string
  workspace: string
  resource: string
  kind: string
  state: string
  choice: string | null
  created_at_unix_ms: number
  resolved_at_unix_ms: number | null
}

export type SafeConflictDetailView = {
  conflict: SafeConflictView
  mode: string
  structured_format: string | null
  ours_available: boolean
  theirs_available: boolean
  manual_allowed: boolean
  manual_max_bytes: number
}

export type SafeConflictResolutionView = {
  conflict: string
  state: 'resolved'
  choice: 'ours' | 'theirs' | 'manual' | 'delete'
  resolved_at_unix_ms: number
}

export type SafeOperationView = {
  operation: string
  plan: string
  snapshot: string
  workspace: string
  revision: number
  state: string
  created_at_unix_ms: number
  updated_at_unix_ms: number
  error_code: string | null
}

export type SafeOperationDetailView = {
  operation: SafeOperationView
  actions: Array<{
    ordinal: number
    resource: string
    kind: string
    target: string
    state: string
    error_code: string | null
  }>
  receipts: Array<{
    ordinal: number
    resource: string
    guarantee: string
    created_at_unix_ms: number
  }>
  rollback_available: boolean
}

export type SafeRollbackReviewView = {
  review_token: string
  operation: SafeOperationView
  actions: Array<{
    ordinal: number
    resource: string
    target: string
    original_kind: string
    guarantee: string
  }>
  requires_individual_confirmation: true
}

export type SyncReviewResult<T> = ({ kind: 'success' } & T) | { kind: 'error'; code: string }

export interface SyncReviewPort {
  buildPlan(workspaceId: string): Promise<SyncReviewResult<{ plan: SafePlanView }>>
  loadDiff(workspaceId: string, planId: string): Promise<SyncReviewResult<{ diff: SafeDiffListView }>>
  applyPlan(workspaceId: string, planId: string): Promise<SyncReviewResult<{ operation: string }>>
  listConflicts(workspaceId: string): Promise<SyncReviewResult<{ conflicts: SafeConflictView[] }>>
  showConflict(workspaceId: string, conflictId: string): Promise<SyncReviewResult<{ conflict: SafeConflictDetailView }>>
  resolveConflict(intent: {
    workspaceId: string
    conflictId: string
    choice: 'ours' | 'theirs' | 'manual' | 'delete'
    manualContent?: string
  }): Promise<SyncReviewResult<{ resolution: SafeConflictResolutionView }>>
  listOperations(workspaceId: string): Promise<SyncReviewResult<{ operations: SafeOperationView[] }>>
  showOperation(workspaceId: string, operationId: string): Promise<SyncReviewResult<{ operation: SafeOperationDetailView }>>
  reviewRollback(workspaceId: string, operationId: string): Promise<SyncReviewResult<{ review: SafeRollbackReviewView }>>
  executeRollback(intent: {
    workspaceId: string
    operationId: string
    reviewToken: string
    confirmations: number[]
  }): Promise<SyncReviewResult<{ operation: SafeOperationView }>>
}

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function naturalNumber(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0
}

function optionalIdentifier(value: unknown): value is string | null {
  return value === null || opaqueIdentifier(value)
}

function safeTarget(value: unknown): value is string {
  if (typeof value !== 'string' || value.length === 0 || value.length > 512) {
    return false
  }
  const separator = value.indexOf(':')
  if (separator <= 0 || separator === value.length - 1) {
    return false
  }
  const root = value.slice(0, separator)
  const segments = value.slice(separator + 1).split('/')
  return (
    opaqueIdentifier(root)
    && segments.every(
      (segment) => segment !== ''
        && segment !== '.'
        && segment !== '..'
        && /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(segment),
    )
  )
}

function safePlanAction(value: unknown): SafePlanAction | null {
  if (
    !isRecord(value)
    || !safeResourceIdentifier(value.resource)
    || typeof value.kind !== 'string'
    || !actionKinds.has(value.kind)
    || !safeTarget(value.target)
    || typeof value.risk !== 'string'
    || !risks.has(value.risk)
    || !opaqueIdentifier(value.backup)
    || !opaqueIdentifier(value.rollback)
    || typeof value.sensitive !== 'boolean'
  ) {
    return null
  }
  return {
    resource: value.resource,
    kind: value.kind,
    target: value.target,
    risk: value.risk as SafePlanAction['risk'],
    backup: value.backup,
    rollback: value.rollback,
    sensitive: value.sensitive,
  }
}

function planView(value: unknown, diagnostics: SafeDiagnostic[]): { plan: SafePlanView } | null {
  if (!isRecord(value) || !Array.isArray(value.actions)) {
    return null
  }
  const actions = value.actions.map(safePlanAction)
  if (
    actions.some((action) => action === null)
    || !opaqueIdentifier(value.id)
    || !opaqueIdentifier(value.workspace)
    || !opaqueIdentifier(value.device_id)
    || !opaqueIdentifier(value.target_snapshot)
    || !naturalNumber(value.base_revision)
    || !naturalNumber(value.next_revision)
  ) {
    return null
  }
  return {
    plan: {
      id: value.id,
      workspace: value.workspace,
      device_id: value.device_id,
      target_snapshot: value.target_snapshot,
      base_revision: value.base_revision,
      next_revision: value.next_revision,
      actions: actions as SafePlanAction[],
      diagnostics,
    },
  }
}

function safeDiff(value: unknown): SafeDiffView | null {
  if (
    !isRecord(value)
    || !safeResourceIdentifier(value.resource)
    || typeof value.kind !== 'string'
    || !diffKinds.has(value.kind)
    || typeof value.sensitive !== 'boolean'
    || typeof value.presentation !== 'string'
    || !diffPresentations.has(value.presentation)
    || (value.content_bytes !== null && !naturalNumber(value.content_bytes))
    || typeof value.preview_truncated !== 'boolean'
    || !optionalIdentifier(value.before_digest)
    || !optionalIdentifier(value.after_digest)
  ) {
    return null
  }
  if (value.sensitive && (value.before_digest !== null || value.after_digest !== null)) {
    return null
  }
  return {
    resource: value.resource,
    kind: value.kind as SafeDiffView['kind'],
    sensitive: value.sensitive,
    presentation: value.presentation as SafeDiffView['presentation'],
    content_bytes: value.content_bytes,
    preview_truncated: value.preview_truncated,
    before_digest: value.before_digest,
    after_digest: value.after_digest,
  }
}

function diffListView(value: unknown): { diff: SafeDiffListView } | null {
  if (!isRecord(value) || !opaqueIdentifier(value.plan) || !Array.isArray(value.diffs)) {
    return null
  }
  const diffs = value.diffs.map(safeDiff)
  return diffs.some((diff) => diff === null)
    ? null
    : { diff: { plan: value.plan, diffs: diffs as SafeDiffView[] } }
}

function safeConflict(value: unknown): SafeConflictView | null {
  if (
    !isRecord(value)
    || !opaqueIdentifier(value.id)
    || !opaqueIdentifier(value.workspace)
    || !safeResourceIdentifier(value.resource)
    || typeof value.kind !== 'string'
    || !conflictKinds.has(value.kind)
    || typeof value.state !== 'string'
    || !conflictStates.has(value.state)
    || (value.choice !== null
      && (typeof value.choice !== 'string' || !resolutionChoices.has(value.choice)))
    || !naturalNumber(value.created_at_unix_ms)
    || (value.resolved_at_unix_ms !== null && !naturalNumber(value.resolved_at_unix_ms))
  ) {
    return null
  }
  return {
    id: value.id,
    workspace: value.workspace,
    resource: value.resource,
    kind: value.kind,
    state: value.state,
    choice: value.choice,
    created_at_unix_ms: value.created_at_unix_ms,
    resolved_at_unix_ms: value.resolved_at_unix_ms,
  }
}

function conflictListView(value: unknown): { conflicts: SafeConflictView[] } | null {
  if (!isRecord(value) || !opaqueIdentifier(value.workspace) || !Array.isArray(value.conflicts)) {
    return null
  }
  const conflicts = value.conflicts.map(safeConflict)
  return conflicts.some((conflict) => conflict === null)
    ? null
    : { conflicts: conflicts as SafeConflictView[] }
}

function conflictDetailView(value: unknown): { conflict: SafeConflictDetailView } | null {
  if (!isRecord(value)) {
    return null
  }
  const conflict = safeConflict(value.conflict)
  if (
    !conflict
    || typeof value.mode !== 'string'
    || !fileModes.has(value.mode)
    || (value.structured_format !== null
      && (typeof value.structured_format !== 'string' || !structuredFormats.has(value.structured_format)))
    || typeof value.ours_available !== 'boolean'
    || typeof value.theirs_available !== 'boolean'
    || typeof value.manual_allowed !== 'boolean'
    || !naturalNumber(value.manual_max_bytes)
    || (!value.manual_allowed && value.manual_max_bytes !== 0)
  ) {
    return null
  }
  return {
    conflict: {
      conflict,
      mode: value.mode,
      structured_format: value.structured_format,
      ours_available: value.ours_available,
      theirs_available: value.theirs_available,
      manual_allowed: value.manual_allowed,
      manual_max_bytes: value.manual_max_bytes,
    },
  }
}

function conflictResolutionView(value: unknown): { resolution: SafeConflictResolutionView } | null {
  if (
    !isRecord(value)
    || !opaqueIdentifier(value.conflict)
    || value.state !== 'resolved'
    || typeof value.choice !== 'string'
    || !resolutionChoices.has(value.choice)
    || !naturalNumber(value.resolved_at_unix_ms)
  ) {
    return null
  }
  return {
    resolution: {
      conflict: value.conflict,
      state: 'resolved',
      choice: value.choice as SafeConflictResolutionView['choice'],
      resolved_at_unix_ms: value.resolved_at_unix_ms,
    },
  }
}

function safeOperation(value: unknown): SafeOperationView | null {
  if (
    !isRecord(value)
    || !opaqueIdentifier(value.operation)
    || !opaqueIdentifier(value.plan)
    || !opaqueIdentifier(value.snapshot)
    || !opaqueIdentifier(value.workspace)
    || !naturalNumber(value.revision)
    || typeof value.state !== 'string'
    || !operationStates.has(value.state)
    || !naturalNumber(value.created_at_unix_ms)
    || !naturalNumber(value.updated_at_unix_ms)
    || !optionalIdentifier(value.error_code)
  ) {
    return null
  }
  return {
    operation: value.operation,
    plan: value.plan,
    snapshot: value.snapshot,
    workspace: value.workspace,
    revision: value.revision,
    state: value.state,
    created_at_unix_ms: value.created_at_unix_ms,
    updated_at_unix_ms: value.updated_at_unix_ms,
    error_code: value.error_code,
  }
}

function operationHistoryView(value: unknown): { operations: SafeOperationView[] } | null {
  if (!isRecord(value) || !opaqueIdentifier(value.workspace) || !Array.isArray(value.operations)) {
    return null
  }
  const operations = value.operations.map(safeOperation)
  return operations.some((operation) => operation === null)
    ? null
    : { operations: operations as SafeOperationView[] }
}

function operationDetailView(value: unknown): { operation: SafeOperationDetailView } | null {
  if (!isRecord(value) || !Array.isArray(value.actions) || !Array.isArray(value.receipts)) {
    return null
  }
  const operation = safeOperation(value.operation)
  const actions = value.actions.flatMap((action) => {
    if (
      !isRecord(action)
      || !naturalNumber(action.ordinal)
      || !safeResourceIdentifier(action.resource)
      || typeof action.kind !== 'string'
      || !actionKinds.has(action.kind)
      || !safeTarget(action.target)
      || typeof action.state !== 'string'
      || !actionStates.has(action.state)
      || !optionalIdentifier(action.error_code)
    ) {
      return []
    }
    return [{
      ordinal: action.ordinal,
      resource: action.resource,
      kind: action.kind,
      target: action.target,
      state: action.state,
      error_code: action.error_code,
    }]
  })
  const receipts = value.receipts.flatMap((receipt) => {
    if (
      !isRecord(receipt)
      || !naturalNumber(receipt.ordinal)
      || !safeResourceIdentifier(receipt.resource)
      || typeof receipt.guarantee !== 'string'
      || !rollbackCapabilities.has(receipt.guarantee)
      || !naturalNumber(receipt.created_at_unix_ms)
    ) {
      return []
    }
    return [{
      ordinal: receipt.ordinal,
      resource: receipt.resource,
      guarantee: receipt.guarantee,
      created_at_unix_ms: receipt.created_at_unix_ms,
    }]
  })
  if (
    !operation
    || actions.length !== value.actions.length
    || receipts.length !== value.receipts.length
    || typeof value.rollback_available !== 'boolean'
  ) {
    return null
  }
  return { operation: { operation, actions, receipts, rollback_available: value.rollback_available } }
}

function rollbackReviewView(value: unknown): { review: SafeRollbackReviewView } | null {
  if (!isRecord(value) || !opaqueIdentifier(value.review_token) || !Array.isArray(value.actions)) {
    return null
  }
  const operation = safeOperation(value.operation)
  const actions = value.actions.flatMap((action) => {
    if (
      !isRecord(action)
      || !naturalNumber(action.ordinal)
      || !safeResourceIdentifier(action.resource)
      || !safeTarget(action.target)
      || typeof action.original_kind !== 'string'
      || !actionKinds.has(action.original_kind)
      || typeof action.guarantee !== 'string'
      || !rollbackCapabilities.has(action.guarantee)
    ) {
      return []
    }
    return [{
      ordinal: action.ordinal,
      resource: action.resource,
      target: action.target,
      original_kind: action.original_kind,
      guarantee: action.guarantee,
    }]
  })
  if (
    !operation
    || actions.length !== value.actions.length
    || value.requires_individual_confirmation !== true
  ) {
    return null
  }
  return {
    review: {
      review_token: value.review_token,
      operation,
      actions,
      requires_individual_confirmation: true,
    },
  }
}

function applyStartView(value: unknown): { operation: string } | null {
  return isRecord(value) && opaqueIdentifier(value.operation) && value.state === 'queued'
    ? { operation: value.operation }
    : null
}

function safeOperationResponse(value: unknown): { operation: SafeOperationView } | null {
  const operation = safeOperation(value)
  return operation ? { operation } : null
}

function invalidIdentifier<T>(): Promise<SyncReviewResult<T>> {
  return Promise.resolve({ kind: 'error', code: 'desktop.workspace_not_registered' })
}

/** 生产环境的 Plan / Diff / Conflict / History 端口。 */
export const tauriSyncReviewPort: SyncReviewPort = {
  buildPlan: (workspaceId) => (
    opaqueIdentifier(workspaceId)
      ? invokeDesktop('workspace_plan', { workspace_id: workspaceId }, planView)
      : invalidIdentifier()
  ),
  loadDiff: (workspaceId, planId) => (
    opaqueIdentifier(workspaceId) && opaqueIdentifier(planId)
      ? invokeDesktop('plan_diff', { workspace_id: workspaceId, plan_id: planId }, diffListView)
      : invalidIdentifier()
  ),
  applyPlan: (workspaceId, planId) => (
    opaqueIdentifier(workspaceId) && opaqueIdentifier(planId)
      ? invokeDesktop('workspace_apply', { workspace_id: workspaceId, plan_id: planId }, applyStartView)
      : invalidIdentifier()
  ),
  listConflicts: (workspaceId) => (
    opaqueIdentifier(workspaceId)
      ? invokeDesktop('conflict_list', { workspace_id: workspaceId }, conflictListView)
      : invalidIdentifier()
  ),
  showConflict: (workspaceId, conflictId) => (
    opaqueIdentifier(workspaceId) && opaqueIdentifier(conflictId)
      ? invokeDesktop('conflict_show', { workspace_id: workspaceId, conflict_id: conflictId }, conflictDetailView)
      : invalidIdentifier()
  ),
  resolveConflict: (intent) => {
    if (
      !opaqueIdentifier(intent.workspaceId)
      || !opaqueIdentifier(intent.conflictId)
      || !resolutionChoices.has(intent.choice)
      || (intent.choice !== 'manual' && intent.manualContent !== undefined)
    ) {
      return invalidIdentifier()
    }
    return invokeDesktop(
      'conflict_resolve',
      {
        workspace_id: intent.workspaceId,
        conflict_id: intent.conflictId,
        choice: intent.choice,
        ...(intent.choice === 'manual' ? { manual_content: intent.manualContent ?? '' } : {}),
      },
      conflictResolutionView,
    )
  },
  listOperations: (workspaceId) => (
    opaqueIdentifier(workspaceId)
      ? invokeDesktop('operation_history', { workspace_id: workspaceId }, operationHistoryView)
      : invalidIdentifier()
  ),
  showOperation: (workspaceId, operationId) => (
    opaqueIdentifier(workspaceId) && opaqueIdentifier(operationId)
      ? invokeDesktop('operation_detail', { workspace_id: workspaceId, operation_id: operationId }, operationDetailView)
      : invalidIdentifier()
  ),
  reviewRollback: (workspaceId, operationId) => (
    opaqueIdentifier(workspaceId) && opaqueIdentifier(operationId)
      ? invokeDesktop('operation_rollback_review', { workspace_id: workspaceId, operation_id: operationId }, rollbackReviewView)
      : invalidIdentifier()
  ),
  executeRollback: (intent) => {
    if (
      !opaqueIdentifier(intent.workspaceId)
      || !opaqueIdentifier(intent.operationId)
      || !opaqueIdentifier(intent.reviewToken)
      || !intent.confirmations.every(naturalNumber)
    ) {
      return invalidIdentifier()
    }
    return invokeDesktop(
      'operation_rollback',
      {
        workspace_id: intent.workspaceId,
        operation_id: intent.operationId,
        review_token: intent.reviewToken,
        confirmations: intent.confirmations,
      },
      safeOperationResponse,
    )
  },
}
