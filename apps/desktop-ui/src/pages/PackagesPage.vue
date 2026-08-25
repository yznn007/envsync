<script setup lang="ts">
import { computed, ref, watch } from 'vue'

export type PackageReviewAction = {
  id: string
  identity: string
  kind: 'install' | 'upgrade' | 'downgrade' | 'uninstall' | 'change_source'
  risk: 'low' | 'medium' | 'high'
  elevation_required: boolean
  policy: 'allow' | 'require_confirmation' | 'deny'
}

const props = withDefaults(defineProps<{
  actions?: PackageReviewAction[]
}>(), {
  actions: () => [],
})

const approved = ref<Set<string>>(new Set())
const notice = ref<string | null>(null)

const actionable = computed(() => props.actions.filter((action) => action.policy !== 'deny'))

function labelFor(kind: PackageReviewAction['kind']) {
  return {
    install: '安装',
    upgrade: '升级',
    downgrade: '降级',
    uninstall: '卸载',
    change_source: '切换来源',
  }[kind]
}

function policyLabel(policy: PackageReviewAction['policy']) {
  return {
    allow: '策略允许',
    require_confirmation: '策略要求确认',
    deny: '策略拒绝',
  }[policy]
}

function toggle(action: PackageReviewAction, checked: boolean) {
  if (action.policy === 'deny') {
    return
  }
  const next = new Set(approved.value)
  if (checked) {
    next.add(action.id)
  } else {
    next.delete(action.id)
  }
  approved.value = next
}

function approveAllAllowed() {
  approved.value = new Set(actionable.value.map((action) => action.id))
  notice.value = '已仅选择策略允许或要求确认的动作。策略拒绝项保持不可批准，提交时仍由 core 重新判定。'
}

watch(
  () => props.actions,
  () => {
    approved.value = new Set()
    notice.value = null
  },
  { deep: true },
)
</script>

<template>
  <section
    class="review-panel security-panel"
    aria-labelledby="packages-title"
  >
    <p class="route-panel__eyebrow">
      Package policy review
    </p>
    <h2 id="packages-title">
      软件包
    </h2>
    <p class="review-panel__copy">
      软件包只可由已保存的计划驱动。这里的选择不是授权：core 会在提交和执行前再次求值 policy；被拒绝的动作永远不能混进批量批准。
    </p>

    <p
      v-if="!actions.length"
      class="review-empty"
      data-packages-empty
      role="status"
    >
      当前没有来自受控 application service 的已保存包计划；未把“没有数据”解释为已收敛。
    </p>

    <template v-else>
      <div class="review-section-heading">
        <h3>计划动作 · {{ actions.length }} 项</h3>
        <button
          class="preference-button"
          data-action="approve-all-allowed-packages"
          type="button"
          @click="approveAllAllowed"
        >
          仅批量选择可审批项
        </button>
      </div>
      <p
        v-if="notice"
        class="review-warning"
        role="status"
      >
        {{ notice }}
      </p>
      <ul class="plan-action-list">
        <li
          v-for="action in actions"
          :key="action.id"
          class="plan-action package-action"
          :data-package-policy="action.policy"
        >
          <div>
            <code>{{ action.identity }}</code>
            <span class="risk-tag">{{ labelFor(action.kind) }}</span>
          </div>
          <div class="security-tags">
            <span class="risk-tag">{{ policyLabel(action.policy) }}</span>
            <span
              v-if="action.elevation_required"
              class="risk-tag risk-tag--warning"
              data-package-elevation
            >需提权</span>
            <span class="risk-tag">{{ action.risk }} risk</span>
          </div>
          <label class="review-confirmation">
            <input
              :checked="approved.has(action.id)"
              :disabled="action.policy === 'deny'"
              :data-package-approval="action.id"
              type="checkbox"
              @change="toggle(action, ($event.target as HTMLInputElement).checked)"
            >
            {{ action.policy === 'deny' ? '此动作已被策略拒绝，不能批准' : '我已审核该软件包动作' }}
          </label>
        </li>
      </ul>
    </template>
  </section>
</template>
