import { createPinia, setActivePinia } from 'pinia'
import { mount } from '@vue/test-utils'

import StatusPage from './StatusPage.vue'
import { useWorkspaceStore } from '../stores/workspace'

describe('StatusPage', () => {
  it('把后端不可达与最后已知状态明确展示为离线，而不是 clean', () => {
    setActivePinia(createPinia())
    const workspace = useWorkspaceStore()
    workspace.setWorkspace({
      workspaceId: 'workspace-01',
      backendKind: 'git',
      deviceId: 'device-01',
      root: { token: 'cap-root-01', label: '已授权根目录' },
    })
    workspace.setStatus({
      workspace: {
        id: 'workspace-01',
        device_id: 'device-01',
        backend_kind: 'git',
      },
      state: 'backend_unreachable',
      backend_reachable: false,
      last_known_revision_at_unix_ms: 1_725_000_000_000,
      revision: 8,
      head: 'snapshot-safe-id',
      draft_head: null,
      resources: [
        {
          resource: 'shell/zsh/main',
          observed: 'modified',
          disposition: 'managed',
          needs_action: true,
        },
      ],
      unfinished_operations: [{ operation: 'operation-01', state: 'preflighted' }],
      pending_actions: 2,
      open_conflicts: 0,
      diagnostics: [{ severity: 'warning', code: 'status.backend_unreachable', resource: null }],
    })

    const wrapper = mount(StatusPage)

    expect(wrapper.get('[data-connection-state]').text()).toContain('后端不可达')
    expect(wrapper.get('[data-last-known-state]').text()).toContain('最后已知状态')
    expect(wrapper.get('[data-next-action]').text()).toContain('检查网络')
    expect(wrapper.text()).not.toContain('同步已完成')
  })
})
