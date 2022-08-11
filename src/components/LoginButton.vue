<template>
  <button @click="initiateGoogleLogin">
    Login with Google
  </button>
</template>

<script setup lang="ts">
import { invoke } from '@tauri-apps/api';

function initiateGoogleLogin() {
  console.log('initiating google login');
}
</script>

<style scoped>
button {
 background-color: red;
 color: white;
 border-radius: 12px;
 padding: 4px 6px;
}
</style>