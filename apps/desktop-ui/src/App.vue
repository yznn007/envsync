<script setup lang="ts">
import { computed, onErrorCaptured, onMounted, watch } from 'vue'
import { RouterLink, RouterView, useRoute } from 'vue-router'

import { navigationItems } from './router'
import { useUiStore } from './stores/ui'

const route = useRoute()
const ui = useUiStore()

const currentLabel = computed(() => String(route.meta.label ?? '工作区'))
const themeLabel = computed(() => {
  const labels = { system: '跟随系统', light: '浅色', dark: '深色' }
  return labels[ui.theme]
})
const contrastLabel = computed(() => (ui.contrast === 'high' ? '高对比' : '标准对比'))

function applyPreferences() {
  document.documentElement.dataset.theme = ui.theme
  document.documentElement.dataset.contrast = ui.contrast
}

function closeDrawer() {
  ui.closeNavigation()
}

onMounted(applyPreferences)
watch([() => ui.theme, () => ui.contrast], applyPreferences)
onErrorCaptured(() => {
  // 原始异常可能带外部输入；边界只记录稳定错误码。
  ui.recordBoundaryError()
  return false
})
</script>

<template>
  <div class="app-shell">
    <aside
      class="side-rail"
      aria-label="EnvSync 控制台"
    >
      <RouterLink
        class="brand-lockup"
        to="/"
        aria-label="返回工作区"
      >
        <span
          class="brand-lockup__mark"
          aria-hidden="true"
        >↻</span>
        <span>
          <span class="brand-lockup__name">EnvSync</span>
          <span class="brand-lockup__subline">受控同步</span>
        </span>
      </RouterLink>

      <p class="rail-heading">
        工作流
      </p>
      <nav
        id="primary-navigation"
        class="primary-navigation"
        aria-label="主导航"
        :data-drawer-open="ui.navigationOpen"
      >
        <RouterLink
          v-for="item in navigationItems"
          :key="item.key"
          class="nav-link"
          :to="item.path"
          :data-nav-key="item.key"
          @click="closeDrawer"
        >
          {{ item.label }}
        </RouterLink>
      </nav>

      <div
        class="side-rail__footer"
        aria-label="显示偏好"
      >
        <button
          class="preference-button"
          type="button"
          @click="ui.cycleTheme"
        >
          主题：{{ themeLabel }}
        </button>
        <button
          class="preference-button"
          type="button"
          @click="ui.toggleContrast"
        >
          对比：{{ contrastLabel }}
        </button>
      </div>
    </aside>

    <main class="workspace">
      <header class="workspace-header">
        <div>
          <p class="route-panel__eyebrow">
            EnvSync / 当前区域
          </p>
          <h1 class="workspace-header__title">
            {{ currentLabel }}
          </h1>
          <p class="workspace-header__meta">
            所有结果均经过脱敏 application service。
          </p>
        </div>
        <div
          class="status-ledger"
          aria-label="同步安全状态：受控"
        >
          <span
            class="status-ledger__dot"
            aria-hidden="true"
          />
          <span class="status-ledger__label">受控</span>
        </div>
        <button
          class="drawer-button"
          type="button"
          aria-controls="primary-navigation"
          :aria-expanded="ui.navigationOpen"
          @click="ui.toggleNavigation"
        >
          导航
        </button>
      </header>

      <section
        v-if="ui.boundaryErrorCode"
        class="error-boundary"
        role="alert"
      >
        <strong>界面需要重新加载。</strong>
        <p>错误码：{{ ui.boundaryErrorCode }}</p>
        <p v-if="ui.lastRequestId">
          请求 ID：{{ ui.lastRequestId }}
        </p>
      </section>

      <RouterView />
    </main>
  </div>
</template>
