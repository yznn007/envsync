import { defineComponent, h } from 'vue'
import { createRouter, createWebHashHistory } from 'vue-router'

import WorkspacePage from './pages/WorkspacePage.vue'

export const navigationItems = [
  { key: 'workspace', label: '工作区', path: '/' },
  { key: 'changes', label: '变更', path: '/changes' },
  { key: 'conflicts', label: '冲突', path: '/conflicts' },
  { key: 'packages', label: '软件包', path: '/packages' },
  { key: 'agents', label: '代理', path: '/agents' },
  { key: 'vault', label: '保险库', path: '/vault' },
  { key: 'devices', label: '设备', path: '/devices' },
  { key: 'history', label: '历史', path: '/history' },
  { key: 'settings', label: '设置', path: '/settings' },
] as const

export type NavigationKey = (typeof navigationItems)[number]['key']

function sectionPage(label: string, key: NavigationKey) {
  return defineComponent({
    name: `EnvSync${key[0]?.toUpperCase()}${key.slice(1)}Page`,
    setup() {
      return () =>
        h('section', { class: 'route-panel', 'aria-labelledby': `${key}-title` }, [
          h('p', { class: 'route-panel__eyebrow' }, '受控工作区'),
          h('h1', { id: `${key}-title` }, label),
          h(
            'p',
            { class: 'route-panel__copy' },
            '此区域只展示经过 application service 脱敏后的状态与待确认操作。',
          ),
        ])
    },
  })
}

const routes = navigationItems.map((item) => ({
  path: item.path,
  name: item.key,
  component: item.key === 'workspace' ? WorkspacePage : sectionPage(item.label, item.key),
  meta: { label: item.label },
}))

const router = createRouter({
  history: createWebHashHistory(),
  routes,
})

export default router
