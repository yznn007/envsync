<script setup lang="ts">
import { computed, ref, watch } from 'vue'

export type BundleReview = {
  id: string
  signer: string
  digest: string
  files: Array<{ path: string; digest: string }>
  capabilities: string[]
  secret_refs: string[]
  version: string
  previous_version: string | null
  added_capabilities: string[]
  state: 'downloaded' | 'inspected' | 'approved' | 'enabled' | 'blocked' | 'revoked'
}

const props = withDefaults(defineProps<{
  bundles?: BundleReview[]
}>(), {
  bundles: () => [],
})

const confirmedCapabilities = ref<Set<string>>(new Set())

function capabilityKey(bundle: BundleReview, capability: string) {
  return `${bundle.id}:${capability}`
}

function toggleCapability(bundle: BundleReview, capability: string, checked: boolean) {
  const next = new Set(confirmedCapabilities.value)
  const key = capabilityKey(bundle, capability)
  if (checked) {
    next.add(key)
  } else {
    next.delete(key)
  }
  confirmedCapabilities.value = next
}

function newCapabilitiesConfirmed(bundle: BundleReview) {
  return bundle.added_capabilities.every((capability) => (
    confirmedCapabilities.value.has(capabilityKey(bundle, capability))
  ))
}

const reviewedCount = computed(() => props.bundles.filter(newCapabilitiesConfirmed).length)

watch(
  () => props.bundles,
  () => {
    confirmedCapabilities.value = new Set()
  },
  { deep: true },
)
</script>

<template>
  <section
    class="review-panel security-panel"
    aria-labelledby="agents-title"
  >
    <p class="route-panel__eyebrow">
      Active content quarantine
    </p>
    <h2 id="agents-title">
      代理
    </h2>
    <p class="review-panel__copy">
      Agent Bundle 是主动内容：即使已下载，quarantine 中的文件也不可从此界面执行。只有 core 验签、policy、审核和能力扩张复审全部通过后，才可能启用。
    </p>

    <p
      v-if="!bundles.length"
      class="review-empty"
      data-bundles-empty
      role="status"
    >
      没有 Bundle manifest 进入受控审核队列。当前不会伪造 signer、能力、SecretRef 或版本差异。
    </p>
    <template v-else>
      <p class="review-warning">
        已完成新增 capability 前端逐项确认：{{ reviewedCount }} / {{ bundles.length }}；确认仅是审核输入，不会直接执行 quarantine 内容。
      </p>
      <ul class="plan-action-list">
        <li
          v-for="bundle in bundles"
          :key="bundle.id"
          class="plan-action bundle-review"
          :data-bundle-id="bundle.id"
        >
          <div>
            <code>{{ bundle.id }}</code>
            <span class="risk-tag">{{ bundle.state }}</span>
          </div>
          <dl class="plan-action__facts">
            <div>
              <dt>Signer</dt>
              <dd><code>{{ bundle.signer }}</code></dd>
            </div>
            <div>
              <dt>Manifest digest</dt>
              <dd><code>{{ bundle.digest }}</code></dd>
            </div>
            <div>
              <dt>版本差异</dt>
              <dd>{{ bundle.previous_version ?? '首次审核' }} → {{ bundle.version }}</dd>
            </div>
          </dl>

          <section class="bundle-review__section">
            <h3>文件 · {{ bundle.files.length }} 项</h3>
            <ul class="security-list">
              <li
                v-for="file in bundle.files"
                :key="file.path"
              >
                <code>{{ file.path }}</code> · <code>{{ file.digest }}</code>
              </li>
            </ul>
          </section>
          <section class="bundle-review__section">
            <h3>声明能力</h3>
            <ul class="security-list">
              <li
                v-for="capability in bundle.capabilities"
                :key="capability"
              >
                <code>{{ capability }}</code>
              </li>
            </ul>
          </section>
          <section class="bundle-review__section">
            <h3>SecretRef</h3>
            <p
              v-if="!bundle.secret_refs.length"
              class="security-muted"
            >
              未声明 SecretRef。
            </p>
            <ul
              v-else
              class="security-list"
            >
              <li
                v-for="reference in bundle.secret_refs"
                :key="reference"
              >
                <code>{{ reference }}</code>
              </li>
            </ul>
          </section>
          <fieldset
            v-if="bundle.added_capabilities.length"
            class="capability-confirmations"
          >
            <legend>新增 capability 必须逐项确认</legend>
            <label
              v-for="capability in bundle.added_capabilities"
              :key="capability"
              class="review-confirmation"
            >
              <input
                :checked="confirmedCapabilities.has(capabilityKey(bundle, capability))"
                :data-capability-confirmation="capability"
                type="checkbox"
                @change="toggleCapability(bundle, capability, ($event.target as HTMLInputElement).checked)"
              >
              我已审核新增能力 <code>{{ capability }}</code>
            </label>
            <p
              v-if="!newCapabilitiesConfirmed(bundle)"
              class="review-warning"
            >
              未完成所有新增能力确认前，core 审批入口必须保持不可用。
            </p>
          </fieldset>
          <p class="review-warning">
            Quarantine 内容从不提供“运行”“打开”或 shell 入口；它只能经受控 Bundle 状态机继续处理。
          </p>
        </li>
      </ul>
    </template>
  </section>
</template>
