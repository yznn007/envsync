<script setup lang="ts">
import { watch } from 'vue'

import OnboardingPage from './OnboardingPage.vue'
import StatusPage from './StatusPage.vue'
import { tauriWorkspaceStatusPort } from '../ports/workspace-status'
import { useWorkspaceStore } from '../stores/workspace'

const workspace = useWorkspaceStore()

async function loadStatus() {
  const current = workspace.workspace
  if (!current) {
    return
  }
  const requestedWorkspaceId = current.workspaceId
  const result = await tauriWorkspaceStatusPort.loadStatus(requestedWorkspaceId)
  if (workspace.workspace?.workspaceId !== requestedWorkspaceId) {
    return
  }
  if (result.kind === 'error') {
    workspace.setFailure(result.code)
    return
  }
  workspace.setStatus(result.status)
}

watch(
  () => workspace.workspace?.workspaceId,
  (workspaceId) => {
    if (workspaceId) {
      void loadStatus()
    }
  },
  { immediate: true },
)
</script>

<template>
  <OnboardingPage v-if="!workspace.workspace" />
  <StatusPage
    v-else
    @refresh-status="loadStatus"
  />
</template>
