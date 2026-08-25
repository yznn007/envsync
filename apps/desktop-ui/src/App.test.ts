import { createPinia } from 'pinia'
import { flushPromises, mount } from '@vue/test-utils'

import App from './App.vue'
import router, { navigationItems } from './router'

async function mountApp() {
  await router.replace('/')
  await router.isReady()
  return mount(App, {
    attachTo: document.body,
    global: {
      plugins: [createPinia(), router],
    },
  })
}

describe('EnvSync desktop shell', () => {
  it('renders every safe-workflow destination and marks the current page', async () => {
    const wrapper = await mountApp()

    expect(wrapper.find('nav[aria-label="主导航"]').exists()).toBe(true)
    expect(wrapper.findAll('[data-nav-key]')).toHaveLength(navigationItems.length)
    expect(
      wrapper.get('nav[aria-label="主导航"] [aria-current="page"]').text(),
    ).toContain('工作区')

    await wrapper.get('[data-nav-key="changes"]').trigger('click')
    await flushPromises()

    expect(router.currentRoute.value.name).toBe('changes')
    expect(
      wrapper.get('nav[aria-label="主导航"] [aria-current="page"]').text(),
    ).toContain('变更')
  })

  it('keeps navigation keyboard reachable and exposes a narrow-screen drawer control', async () => {
    const wrapper = await mountApp()
    const workspace = wrapper.get('[data-nav-key="workspace"]')
    ;(workspace.element as HTMLAnchorElement).focus()
    expect(document.activeElement).toBe(workspace.element)

    const drawer = wrapper.get('[aria-controls="primary-navigation"]')
    expect(drawer.attributes('aria-expanded')).toBe('false')
    await drawer.trigger('click')
    expect(drawer.attributes('aria-expanded')).toBe('true')
    expect(wrapper.get('nav[aria-label="主导航"]').attributes('data-drawer-open')).toBe('true')
  })
})
