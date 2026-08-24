import { invoke } from '@tauri-apps/api/core'

import { tauriWorkspaceStatusPort } from './workspace-status'

vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn() }))

const invokeMock = vi.mocked(invoke)

describe('tauriWorkspaceStatusPort', () => {
  beforeEach(() => {
    invokeMock.mockReset()
  })

  it('仅以 workspace ID 查询状态，并投影后端、head、漂移和安全诊断', async () => {
    invokeMock.mockResolvedValue({
      schema_version: 1,
      request_id: 'desktop-status-01',
      status: 'ok',
      data: {
        workspace: { id: 'workspace-01', device_id: 'device-01', backend_kind: 'git' },
        state: 'drifted',
        backend_reachable: true,
        last_known_revision_at_unix_ms: null,
        revision: 12,
        head: 'snapshot-01',
        draft_head: 'snapshot-02',
        resources: [
          {
            resource: 'shell/zsh/main',
            observed: 'modified',
            disposition: 'managed',
            needs_action: true,
            local_path: '/private/should-not-reach-ui',
          },
        ],
        unfinished_operations: [{ operation: 'operation-01', state: 'preflighted' }],
        pending_actions: 2,
        open_conflicts: 1,
      },
      diagnostics: [
        {
          severity: 'warning',
          code: 'status.backend_warning',
          resource: 'shell/zsh/main',
          detail: '/private/should-not-reach-ui',
        },
      ],
    })

    const result = await tauriWorkspaceStatusPort.loadStatus('workspace-01')

    expect(invokeMock).toHaveBeenCalledWith(
      'workspace_status',
      expect.objectContaining({
        request: expect.objectContaining({ data: { workspace_id: 'workspace-01' } }),
      }),
    )
    expect(result).toEqual({
      kind: 'success',
      status: expect.objectContaining({
        state: 'drifted',
        head: 'snapshot-01',
        pending_actions: 2,
        open_conflicts: 1,
        resources: [
          {
            resource: 'shell/zsh/main',
            observed: 'modified',
            disposition: 'managed',
            needs_action: true,
          },
        ],
        diagnostics: [
          {
            severity: 'warning',
            code: 'status.backend_warning',
            resource: 'shell/zsh/main',
          },
        ],
      }),
    })
    expect(JSON.stringify(result)).not.toContain('/private')
  })
})
