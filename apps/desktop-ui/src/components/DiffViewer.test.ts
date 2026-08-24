import { mount } from '@vue/test-utils'

import DiffViewer from './DiffViewer.vue'
import type { SafeDiffView } from '../ports/sync-review'

const plainDiff: SafeDiffView = {
  resource: 'shell/zsh/main',
  kind: 'modified',
  sensitive: false,
  presentation: 'managed_block',
  content_bytes: 42,
  preview_truncated: false,
  before_digest: 'before-safe-digest',
  after_digest: 'after-safe-digest',
}

describe('DiffViewer', () => {
  it('区分受管区块、结构化、二进制、新增与删除的无内容摘要', () => {
    const wrapper = mount(DiffViewer, {
      props: {
        diffs: [
          plainDiff,
          { ...plainDiff, resource: 'config/json', presentation: 'structured' },
          { ...plainDiff, resource: 'assets/icon', presentation: 'binary' },
          { ...plainDiff, resource: 'new/file', kind: 'added', presentation: 'text' },
          { ...plainDiff, resource: 'old/file', kind: 'removed', presentation: 'content_summary' },
        ],
      },
    })

    expect(wrapper.text()).toContain('仅受管区块发生变更')
    expect(wrapper.text()).toContain('结构化键差异摘要')
    expect(wrapper.text()).toContain('二进制内容摘要')
    expect(wrapper.text()).toContain('新增')
    expect(wrapper.text()).toContain('删除')
    expect(wrapper.text()).toContain('文件正文、绝对路径和秘密不会传入界面')
  })

  it('秘密只显示“值已更改”，不会渲染 digest 或传入的 canary', () => {
    const canary = 'DIFF_SECRET_CANARY_never_render'
    const wrapper = mount(DiffViewer, {
      props: {
        diffs: [{
          ...plainDiff,
          resource: 'secret/token',
          sensitive: true,
          presentation: 'secret',
          content_bytes: null,
          preview_truncated: true,
          before_digest: null,
          after_digest: null,
        }],
      },
    })

    expect(wrapper.get('[data-secret-diff]').text()).toContain('值已更改')
    expect(wrapper.text()).not.toContain(canary)
    expect(wrapper.text()).not.toContain('before-safe-digest')
    expect(wrapper.find('.diff-card__digests').exists()).toBe(false)
  })

  it('对大量差异采用窗口化渲染并保留截断提示', async () => {
    const diffs = Array.from({ length: 240 }, (_, index) => ({
      ...plainDiff,
      resource: `config/item-${index}`,
      preview_truncated: index === 0,
    }))
    const wrapper = mount(DiffViewer, {
      attachTo: document.body,
      props: { diffs, rowHeight: 80 },
    })

    expect(wrapper.findAll('.diff-card').length).toBeLessThan(diffs.length)
    expect(wrapper.get('[data-diff-truncated]').text()).toContain('窗口化渲染')
    expect(wrapper.get('[data-diff-window]').text()).toContain('/ 240 项')

    const viewport = wrapper.get('[data-diff-viewport]').element as HTMLElement
    Object.defineProperty(viewport, 'clientHeight', { configurable: true, value: 160 })
    viewport.scrollTop = 8_000
    await wrapper.get('[data-diff-viewport]').trigger('scroll')
    expect(wrapper.get('[data-diff-window]').text()).not.toContain('1–')
  })
})
