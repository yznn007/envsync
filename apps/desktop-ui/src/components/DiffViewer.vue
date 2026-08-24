<script setup lang="ts">
import { computed, ref } from 'vue'

import type { SafeDiffView } from '../ports/sync-review'

const props = withDefaults(defineProps<{
  diffs: SafeDiffView[]
  /** 单行预计高度；仅用于列表窗口化，不参与安全判断。 */
  rowHeight?: number
  /** 可视区域前后保留的行数。 */
  overscan?: number
}>(), {
  rowHeight: 96,
  overscan: 5,
})

const viewport = ref<HTMLElement | null>(null)
const scrollTop = ref(0)
const viewportHeight = ref(480)

const firstVisible = computed(() => Math.floor(scrollTop.value / props.rowHeight))
const visibleCount = computed(() => Math.ceil(viewportHeight.value / props.rowHeight))
const windowStart = computed(() => Math.max(0, firstVisible.value - props.overscan))
const windowEnd = computed(() => Math.min(
  props.diffs.length,
  firstVisible.value + visibleCount.value + props.overscan,
))
const renderedDiffs = computed(() => props.diffs.slice(windowStart.value, windowEnd.value))

const kindLabel: Record<SafeDiffView['kind'], string> = {
  added: '新增',
  removed: '删除',
  modified: '修改',
}

const presentationLabel: Record<SafeDiffView['presentation'], string> = {
  secret: '值已更改',
  text: '文本内容摘要',
  structured: '结构化键差异摘要',
  managed_block: '仅受管区块发生变更',
  binary: '二进制内容摘要',
  content_summary: '内容变更摘要',
}

function onScroll() {
  if (!viewport.value) {
    return
  }
  scrollTop.value = viewport.value.scrollTop
  viewportHeight.value = viewport.value.clientHeight || viewportHeight.value
}

function digestLabel(digest: string | null) {
  return digest ? digest.slice(0, 12) : '未提供'
}
</script>

<template>
  <section
    class="diff-viewer"
    aria-label="计划差异摘要"
  >
    <p
      v-if="!diffs.length"
      class="review-empty"
      data-diff-empty
    >
      当前计划没有需要应用的动作。
    </p>
    <template v-else>
      <p
        class="diff-viewer__notice"
        data-diff-boundary
      >
        差异仅包含经 core 审核的摘要；文件正文、绝对路径和秘密不会传入界面。
      </p>
      <div
        ref="viewport"
        class="diff-viewer__viewport"
        data-diff-viewport
        tabindex="0"
        @scroll="onScroll"
      >
        <div
          class="diff-viewer__spacer"
          :style="{ height: `${diffs.length * rowHeight}px` }"
        >
          <ul
            class="diff-viewer__list"
            :style="{ transform: `translateY(${windowStart * rowHeight}px)` }"
          >
            <li
              v-for="diff in renderedDiffs"
              :key="`${diff.resource}:${diff.kind}`"
              class="diff-card"
              :data-diff-presentation="diff.presentation"
              :style="{ minHeight: `${rowHeight}px` }"
            >
              <div class="diff-card__heading">
                <code>{{ diff.resource }}</code>
                <span class="risk-tag">{{ kindLabel[diff.kind] }}</span>
              </div>
              <p class="diff-card__summary">
                {{ presentationLabel[diff.presentation] }}
                <template v-if="!diff.sensitive && diff.content_bytes !== null">
                  · {{ diff.content_bytes }} B
                </template>
              </p>
              <p
                v-if="diff.sensitive"
                class="diff-card__secret"
                data-secret-diff
              >
                值已更改；不会显示摘要、正文或大小。
              </p>
              <dl
                v-else
                class="diff-card__digests"
              >
                <div>
                  <dt>变更前</dt>
                  <dd>{{ digestLabel(diff.before_digest) }}</dd>
                </div>
                <div>
                  <dt>变更后</dt>
                  <dd>{{ digestLabel(diff.after_digest) }}</dd>
                </div>
              </dl>
              <p
                v-if="diff.preview_truncated"
                class="diff-card__truncated"
                data-diff-truncated
              >
                内容较大或受保护，已保持摘要模式并使用窗口化渲染。
              </p>
            </li>
          </ul>
        </div>
      </div>
      <p
        class="diff-viewer__count"
        data-diff-window
      >
        已窗口化渲染 {{ windowStart + 1 }}–{{ windowEnd }} / {{ diffs.length }} 项。
      </p>
    </template>
  </section>
</template>
