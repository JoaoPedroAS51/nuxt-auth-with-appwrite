import { LocalScheme, Token as BaseToken,  } from '~auth/runtime'

function removeTokenPrefix(
  token,
  tokenType
) {
  if (!token || !tokenType || typeof token !== 'string') {
    return token
  }

  return token.replace(tokenType + ' ', '')
}

class Token extends BaseToken {
  _setAppwriteToken(tokenValue) {
    const token = removeTokenPrefix(tokenValue, this.scheme.options.token.type)
    this.scheme.$auth.ctx.$appwrite.setJWT(token)
  }

  set (tokenValue) {
    const token = super.set(tokenValue)

    if (typeof token === 'string') {
      this._setAppwriteToken(token)
    }

    return token
  }

  sync () {
    const token =  super.sync()

    if (typeof token === 'string') {
      this._setAppwriteToken(token)
    }

    return token
  }

  reset () {
    super.reset()
    this._setAppwriteToken('')
  }
}

export default class SupabaseScheme extends LocalScheme {
    constructor($auth, options, ...defaults) {
      super($auth, options, ...defaults);
      this.token = new Token(this, this.$auth.$storage);
    }

    async login(options) {
        const { email, password } = options

        await this.$auth.ctx.$appwrite.account.createSession(email, password)
            .catch((err) => {
                this.$auth.callOnError(err)
                return Promise.reject(err, { method: 'login' })
            })

        await this.$auth.ctx.$appwrite.account.createJWT()
            .then((res) => {
                this.updateTokens(res)
            })
            .catch((err) => {
                this.$auth.callOnError(err)
                return Promise.reject(err, { method: 'login' })
            })

        await this.fetchUser()
    }

    fetchUser() {
        if (!this.check().valid) {
            return Promise.resolve()
        }

        return this.$auth.ctx.$appwrite.account.get()
            .then((user) => {
                this.$auth.setUser(user)
            }).catch((err) => {
                this.$auth.callOnError(err, { method: 'fetchUser' });
                return Promise.reject(err);
            });
    }

    logout() {
        return this.$auth.ctx.$appwrite.account.deleteSession('current')
            .then(() => {
                this.$auth.reset()
            }).catch((err) => {
                this.$auth.callOnError(err, { method: 'logout' });
                return Promise.reject(err);
          });
    }

    updateTokens(response) {
        this.token.set(response.jwt);
    }
}
