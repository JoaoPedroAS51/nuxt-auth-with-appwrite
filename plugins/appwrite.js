import { Appwrite } from "appwrite";


export default (ctx, inject) => {
  // Init your Web SDK
  const appwrite = new Appwrite();

  appwrite
    .setEndpoint('https://aploscreative.dev/v1') // Set only when using self-hosted solution
    .setProject('60aeec8c93f11');

  inject('appwrite', appwrite)
}
