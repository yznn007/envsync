/**
 * Vault 与设备管理的受限桌面端口。
 *
 * 包计划和 Bundle manifest 尚没有可持久化的 application-service 来源，因此它们的页面
 * 只接收测试或未来审核流注入的 View，不在这里伪造 native 调用。此模块仅桥接已经由
 * core 暴露的 Vault metadata 与设备轮换操作。Vault 值绝不通过 WebView IPC 传入。
 */

import {
  invokeDesktop,
  opaqueIdentifier,
  safeResourceIdentifier,
  type SafeDiagnostic,
} from './tauri-api'

type JsonRecord = Record<string, unknown>

const deviceRoles = new Set(['admin', 'member'])
const rotationStages = new Set([
  'prepared',
  'envelopes_published',
  'head_published',
  'rewrapping',
  'complete',
])
export type SafeVaultMetadataView = {
  workspace: string
  index_missing: boolean
  entries: Array<{
    id: string
    updated_at_unix_ms: number
    referenced_by: string[]
  }>
}

export type SafeDeviceListView = {
  workspace: string
  key_epoch: number
  membership_sequence: number
  devices: Array<{
    device: string
    role: 'admin' | 'member'
    added_at_sequence: number
    is_self: boolean
    has_current_envelope: boolean
  }>
}

export type SafeDeviceRevocationView = {
  revoked: string
  from_epoch: number
  to_epoch: number
  stage: 'prepared' | 'envelopes_published' | 'head_published' | 'rewrapping' | 'complete'
  envelopes: number
  pending_rewrap: number
  resumed: boolean
}

export type SecurityReviewResult<T> = ({ kind: 'success' } & T) | { kind: 'error'; code: string }

/** 可替换的安全管理端口，页面测试不会接触 Tauri。 */
export interface SecurityReviewPort {
  loadVaultMetadata(workspaceId: string): Promise<SecurityReviewResult<{ vault: SafeVaultMetadataView }>>
  listDevices(workspaceId: string): Promise<SecurityReviewResult<{ devices: SafeDeviceListView }>>
  revokeDevice(intent: {
    workspaceId: string
    deviceId: string
    confirmation: string
  }): Promise<SecurityReviewResult<{ revocation: SafeDeviceRevocationView }>>
}

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function naturalNumber(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0
}

function secretEntry(value: unknown): SafeVaultMetadataView['entries'][number] | null {
  if (!isRecord(value) || !safeResourceIdentifier(value.id) || !naturalNumber(value.updated_at_unix_ms)) {
    return null
  }
  if (!Array.isArray(value.referenced_by) || !value.referenced_by.every(safeResourceIdentifier)) {
    return null
  }
  return {
    id: value.id,
    updated_at_unix_ms: value.updated_at_unix_ms,
    referenced_by: value.referenced_by,
  }
}

function vaultMetadataView(value: unknown): { vault: SafeVaultMetadataView } | null {
  if (!isRecord(value) || !opaqueIdentifier(value.workspace) || typeof value.index_missing !== 'boolean') {
    return null
  }
  if (!Array.isArray(value.entries)) {
    return null
  }
  const entries = value.entries.map(secretEntry)
  return entries.some((entry) => entry === null)
    ? null
    : {
        vault: {
          workspace: value.workspace,
          index_missing: value.index_missing,
          entries: entries as SafeVaultMetadataView['entries'],
        },
      }
}

function deviceMetadata(value: unknown): SafeDeviceListView['devices'][number] | null {
  if (
    !isRecord(value)
    || !opaqueIdentifier(value.device)
    || typeof value.role !== 'string'
    || !deviceRoles.has(value.role)
    || !naturalNumber(value.added_at_sequence)
    || typeof value.is_self !== 'boolean'
    || typeof value.has_current_envelope !== 'boolean'
  ) {
    return null
  }
  return {
    device: value.device,
    role: value.role as SafeDeviceListView['devices'][number]['role'],
    added_at_sequence: value.added_at_sequence,
    is_self: value.is_self,
    has_current_envelope: value.has_current_envelope,
  }
}

function deviceListView(value: unknown): { devices: SafeDeviceListView } | null {
  if (
    !isRecord(value)
    || !opaqueIdentifier(value.workspace)
    || !naturalNumber(value.key_epoch)
    || !naturalNumber(value.membership_sequence)
    || !Array.isArray(value.devices)
  ) {
    return null
  }
  const devices = value.devices.map(deviceMetadata)
  return devices.some((device) => device === null)
    ? null
    : {
        devices: {
          workspace: value.workspace,
          key_epoch: value.key_epoch,
          membership_sequence: value.membership_sequence,
          devices: devices as SafeDeviceListView['devices'],
        },
      }
}

function deviceRevocationView(value: unknown): { revocation: SafeDeviceRevocationView } | null {
  if (
    !isRecord(value)
    || !opaqueIdentifier(value.revoked)
    || !naturalNumber(value.from_epoch)
    || !naturalNumber(value.to_epoch)
    || typeof value.stage !== 'string'
    || !rotationStages.has(value.stage)
    || !naturalNumber(value.envelopes)
    || !naturalNumber(value.pending_rewrap)
    || typeof value.resumed !== 'boolean'
  ) {
    return null
  }
  return {
    revocation: {
      revoked: value.revoked,
      from_epoch: value.from_epoch,
      to_epoch: value.to_epoch,
      stage: value.stage as SafeDeviceRevocationView['stage'],
      envelopes: value.envelopes,
      pending_rewrap: value.pending_rewrap,
      resumed: value.resumed,
    },
  }
}

function invalidWorkspace<T>(): Promise<SecurityReviewResult<T>> {
  return Promise.resolve({ kind: 'error', code: 'desktop.workspace_not_registered' })
}

/** 生产环境的 Vault / device Tauri 端口。 */
export const tauriSecurityReviewPort: SecurityReviewPort = {
  loadVaultMetadata: (workspaceId) => (
    opaqueIdentifier(workspaceId)
      ? invokeDesktop('vault_metadata', { workspace_id: workspaceId }, vaultMetadataView)
      : invalidWorkspace()
  ),
  listDevices: (workspaceId) => (
    opaqueIdentifier(workspaceId)
      ? invokeDesktop('device_list', { workspace_id: workspaceId }, deviceListView)
      : invalidWorkspace()
  ),
  revokeDevice: (intent) => {
    if (
      !opaqueIdentifier(intent.workspaceId)
      || !opaqueIdentifier(intent.deviceId)
      || intent.confirmation !== intent.deviceId
    ) {
      return invalidWorkspace()
    }
    return invokeDesktop(
      'device_revoke',
      {
        workspace_id: intent.workspaceId,
        device_id: intent.deviceId,
        confirmation: intent.confirmation,
      },
      deviceRevocationView,
    )
  },
}

export type { SafeDiagnostic }
