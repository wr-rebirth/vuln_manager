import { createRouter, createWebHistory } from 'vue-router'
import VulnerabilityList from '../views/VulnerabilityList.vue'

const routes = [
  {
    path: '/',
    name: 'home',
    component: VulnerabilityList
  }
]

const router = createRouter({
  history: createWebHistory(process.env.BASE_URL),
  routes
})

export default router 