<template>
  <div class="bg-blue-300">
    <div>user --> {{ $auth.user }}</div>

    <h1>Login</h1>

    <input type="text" v-model="email" />
    <input type="text" v-model="password" />

    <button
      class="p-5 bg-green-300 text-white font-bold rounded"
      v-on:click="login()"
    >
      Login Perro
    </button>
    <button
      class="p-5 bg-red-300 text-white font-bold rounded"
      v-on:click="logout()"
    >
      Logout Perro
    </button>
  </div>
</template>

<script>
export default {
  middleware: ['auth'],
  data: () => ({
    email: 'aus@gmail.com',
    password: 'sonic123',
  }),
  methods: {
    async login() {
      await this.$auth
        .loginWith('customStrategy', {
          email: this.email,
          password: this.password,
        })
        .then((response) => {
          console.log(response)
        })
        .catch((err) => {
          console.error(err)
        })
    },
    async logout() {
      await this.$auth
        .logout()
        .catch((err) => console.error(err))
    },
  },
}
</script>

<style>
</style>
