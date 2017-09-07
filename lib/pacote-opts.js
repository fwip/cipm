'use strict'

const Buffer = require('safe-buffer').Buffer

const crypto = require('crypto')
const path = require('path')

let effectiveOwner

const npmSession = crypto.randomBytes(8).toString('hex')

module.exports = pacoteOpts
function pacoteOpts (npmOpts, moreOpts) {
  const ownerStats = calculateOwner()
  const opts = {
    cache: path.join(npmOpts['cache'], '_cacache'),
    ca: npmOpts['ca'],
    cert: npmOpts['cert'],
    git: npmOpts['git'],
    key: npmOpts['key'],
    localAddress: npmOpts['local-address'],
    loglevel: npmOpts['loglevel'],
    maxSockets: +npmOpts['maxsockets'],
    npmSession: npmSession,
    offline: npmOpts['offline'],
    projectScope: getProjectScope((npmOpts.rootPkg || moreOpts.rootPkg).name),
    proxy: npmOpts['https-proxy'] || npmOpts['proxy'],
    refer: 'cipm',
    registry: npmOpts['registry'],
    retry: {
      retries: npmOpts['fetch-retries'],
      factor: npmOpts['fetch-retry-factor'],
      minTimeout: npmOpts['fetch-retry-mintimeout'],
      maxTimeout: npmOpts['fetch-retry-maxtimeout']
    },
    strictSSL: npmOpts['strict-ssl'],
    userAgent: npmOpts['user-agent'],

    dmode: parseInt('0777', 8) & (~npmOpts['umask']),
    fmode: parseInt('0666', 8) & (~npmOpts['umask']),
    umask: npmOpts['umask']
  }

  if (ownerStats.uid != null || ownerStats.gid != null) {
    Object.assign(opts, ownerStats)
  }

  Object.keys(npmOpts).forEach(k => {
    const authMatchGlobal = k.match(
      /^(_authToken|username|_password|password|email|always-auth|_auth)$/
    )
    const authMatchScoped = k[0] === '/' && k.match(
      /(.*):(_authToken|username|_password|password|email|always-auth|_auth)$/
    )

    // if it matches scoped it will also match global
    if (authMatchGlobal || authMatchScoped) {
      let nerfDart = null
      let key = null
      let val = null

      if (!opts.auth) { opts.auth = {} }

      if (authMatchScoped) {
        nerfDart = authMatchScoped[1]
        key = authMatchScoped[2]
        val = npmOpts[k]
        if (!opts.auth[nerfDart]) {
          opts.auth[nerfDart] = {
            alwaysAuth: !!npmOpts['always-auth']
          }
        }
      } else {
        key = authMatchGlobal[1]
        val = npmOpts[k]
        opts.auth.alwaysAuth = !!npmOpts['always-auth']
      }

      const auth = authMatchScoped ? opts.auth[nerfDart] : opts.auth
      if (key === '_authToken') {
        auth.token = val
      } else if (key.match(/password$/i)) {
        auth.password =
        // the config file stores password auth already-encoded. pacote expects
        // the actual username/password pair.
        Buffer.from(val, 'base64').toString('utf8')
      } else if (key === 'always-auth') {
        auth.alwaysAuth = val === 'false' ? false : !!val
      } else {
        auth[key] = val
      }
    }

    if (k[0] === '@') {
      if (!opts.scopeTargets) { opts.scopeTargets = {} }
      opts.scopeTargets[k.replace(/:registry$/, '')] = npmOpts[k]
    }
  })

  Object.keys(moreOpts || {}).forEach((k) => {
    opts[k] = moreOpts[k]
  })

  return opts
}

function calculateOwner () {
  if (!effectiveOwner) {
    effectiveOwner = { uid: 0, gid: 0 }

    // Pretty much only on windows
    if (!process.getuid) {
      return effectiveOwner
    }

    effectiveOwner.uid = +process.getuid()
    effectiveOwner.gid = +process.getgid()

    if (effectiveOwner.uid === 0) {
      if (process.env.SUDO_UID) effectiveOwner.uid = +process.env.SUDO_UID
      if (process.env.SUDO_GID) effectiveOwner.gid = +process.env.SUDO_GID
    }
  }

  return effectiveOwner
}

function getProjectScope (pkgName) {
  const sep = pkgName.indexOf('/')
  if (sep === -1) {
    return ''
  } else {
    return pkgName.slice(0, sep)
  }
}
