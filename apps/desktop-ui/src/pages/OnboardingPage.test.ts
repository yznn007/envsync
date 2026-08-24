import { createPinia, setActivePinia } from 'pinia'
import { flushPromises, mount } from '@vue/test-utils'

import OnboardingPage from './OnboardingPage.vue'
import type { OnboardingPort } from '../ports/onboarding'
import { useWorkspaceStore } from '../stores/workspace'

describe('OnboardingPage', () => {
  it('禁用尚未支持的 Gist，并在创建 Local 工作区后只保存安全 view model', async () => {
    setActivePinia(createPinia())
    const port: OnboardingPort = {
      selectRoot: vi.fn().mockResolvedValue({
        kind: 'success',
        root: { token: 'cap-root-01', label: '已授权根目录' },
      }),
      createWorkspace: vi.fn().mockResolvedValue({
        kind: 'success',
        workspace: {
          workspaceId: 'workspace-01',
          backendKind: 'local',
          deviceId: 'device-01',
          root: { token: 'cap-root-01', label: '已授权根目录' },
        },
      }),
      openWorkspace: vi.fn(),
    }

    const wrapper = mount(OnboardingPage, { props: { port } })

    const gist = wrapper.get('[data-backend="gist"]')
    expect(gist.attributes('disabled')).toBeDefined()
    expect(gist.text()).toContain('尚不可用')

    await wrapper.get('[data-action="select-root"]').trigger('click')
    await flushPromises()
    await wrapper.get('[data-action="create-workspace"]').trigger('click')
    await flushPromises()

    expect(port.createWorkspace).toHaveBeenCalledWith({
      backendKind: 'local',
      deviceProfile: '此设备',
      rootCapabilityToken: 'cap-root-01',
    })
    expect(useWorkspaceStore().workspace).toEqual({
      workspaceId: 'workspace-01',
      backendKind: 'local',
      deviceId: 'device-01',
      root: { token: 'cap-root-01', label: '已授权根目录' },
    })
    expect(wrapper.text()).not.toContain('创建失败')
  })

  it('创建 Git 时仅提交远端 URL 与无明文认证方式，不把连接信息写入 store', async () => {
    setActivePinia(createPinia())
    const port: OnboardingPort = {
      selectRoot: vi.fn().mockResolvedValue({
        kind: 'success',
        root: { token: 'cap-root-git', label: '已授权根目录' },
      }),
      createWorkspace: vi.fn().mockResolvedValue({
        kind: 'success',
        workspace: {
          workspaceId: 'workspace-git',
          backendKind: 'git',
          deviceId: 'device-git',
          root: { token: 'cap-root-git', label: '已授权根目录' },
        },
      }),
      openWorkspace: vi.fn(),
    }
    const wrapper = mount(OnboardingPage, { props: { port } })

    await wrapper.get('[data-backend="git"]').trigger('click')
    await wrapper.get('[data-git-remote-url]').setValue('ssh://git@example.com/team/envsync.git')
    await wrapper.get('[data-git-auth="credential-helper"]').trigger('click')
    await wrapper.get('[data-action="select-root"]').trigger('click')
    await flushPromises()
    await wrapper.get('[data-action="create-workspace"]').trigger('click')
    await flushPromises()

    expect(port.createWorkspace).toHaveBeenCalledWith({
      backendKind: 'git',
      deviceProfile: '此设备',
      rootCapabilityToken: 'cap-root-git',
      remoteUrl: 'ssh://git@example.com/team/envsync.git',
      gitAuth: 'credential-helper',
    })
    expect(useWorkspaceStore().workspace).toEqual({
      workspaceId: 'workspace-git',
      backendKind: 'git',
      deviceId: 'device-git',
      root: { token: 'cap-root-git', label: '已授权根目录' },
    })
    expect(JSON.stringify(useWorkspaceStore().workspace)).not.toContain('example.com')
  })
})
