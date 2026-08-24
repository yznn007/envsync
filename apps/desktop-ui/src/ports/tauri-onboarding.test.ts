import { invoke } from '@tauri-apps/api/core'

import { tauriOnboardingPort } from './tauri-onboarding'

vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn() }))

const invokeMock = vi.mocked(invoke)

describe('tauriOnboardingPort', () => {
  beforeEach(() => {
    invokeMock.mockReset()
  })

  it('只向原生 command 发送版本化 token 意图，并从响应中投影安全工作区 view', async () => {
    invokeMock.mockResolvedValue({
      schema_version: 1,
      request_id: 'desktop-response-01',
      status: 'ok',
      data: {
        workspace: {
          id: 'workspace-01',
          device_id: 'device-01',
          backend_kind: 'local',
          backend_path: '/private/backend',
        },
        root: {
          token: 'cap-root-01',
          label: '/private/authorized-root',
        },
      },
      diagnostics: [],
    })

    const result = await tauriOnboardingPort.createWorkspace({
      backendKind: 'local',
      deviceProfile: '此设备',
      rootCapabilityToken: 'cap-root-01',
    })

    expect(invokeMock).toHaveBeenCalledWith(
      'onboarding_create_workspace',
      expect.objectContaining({
        request: expect.objectContaining({
          schema_version: 1,
          request_id: expect.stringMatching(/^desktop-[A-Za-z0-9._-]+$/),
          data: {
            backend_kind: 'local',
            device_profile: '此设备',
            root_capability_token: 'cap-root-01',
          },
        }),
      }),
    )
    expect(result).toEqual({
      kind: 'success',
      workspace: {
        workspaceId: 'workspace-01',
        backendKind: 'local',
        deviceId: 'device-01',
        root: { token: 'cap-root-01', label: '已授权目录' },
      },
    })
    expect(JSON.stringify(result)).not.toContain('/private')
  })

  it('把原生失败收敛为稳定错误码，不转发诊断原文', async () => {
    invokeMock.mockResolvedValue({
      schema_version: 1,
      request_id: 'desktop-response-02',
      status: 'error',
      data: null,
      diagnostics: [
        {
          severity: 'blocking',
          code: 'desktop.root_selection_cancelled',
          detail: '/private/should-not-reach-ui',
        },
      ],
    })

    await expect(tauriOnboardingPort.selectRoot()).resolves.toEqual({
      kind: 'error',
      code: 'desktop.root_selection_cancelled',
    })
  })

  it('Git intent 只携带远端和无明文认证方式', async () => {
    invokeMock.mockResolvedValue({
      schema_version: 1,
      request_id: 'desktop-response-03',
      status: 'error',
      data: null,
      diagnostics: [{ severity: 'blocking', code: 'desktop.git_auth_required', resource: null }],
    })

    await tauriOnboardingPort.createWorkspace({
      backendKind: 'git',
      deviceProfile: '此设备',
      rootCapabilityToken: 'cap-root-git',
      remoteUrl: 'ssh://git@example.com/team/envsync.git',
      gitAuth: 'ssh-agent',
    })

    expect(invokeMock).toHaveBeenCalledWith(
      'onboarding_create_workspace',
      expect.objectContaining({
        request: expect.objectContaining({
          data: {
            backend_kind: 'git',
            device_profile: '此设备',
            root_capability_token: 'cap-root-git',
            remote_url: 'ssh://git@example.com/team/envsync.git',
            git_auth: 'ssh-agent',
          },
        }),
      }),
    )
  })
})
