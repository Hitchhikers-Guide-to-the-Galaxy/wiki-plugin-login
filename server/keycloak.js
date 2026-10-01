// wiki-plugin-login — the Keycloak half, CommonJS, no dependencies.
//
// Two credentials, two jobs:
//   * the farm's own `wiki` client (argv.oauth2_clientID/Secret, the same
//     block every wikiDomains entry carries) PROVES a person's current
//     password with a Resource Owner Password grant — no admin right needed;
//   * the `wiki-login` service account (secret in a mode-600 file, never in
//     the config) RESETS passwords and CREATES users through the Admin API,
//     holding only realm-management view-users + manage-users.
// Nothing here ever logs a password or a token.

const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')

const DEFAULT_SECRET = path.join(os.homedir(), '.config', 'wiki-login', 'secret')

// Derive base + realm from the token URL the farm already has, so the plugin
// follows the farm's Keycloak without its own config.
const endpoints = argv => {
  const tokenUrl = argv.oauth2_TokenURL || process.env.WIKI_LOGIN_TOKEN_URL || ''
  const m = tokenUrl.match(/^(https?:\/\/[^/]+)\/realms\/([^/]+)\//)
  if (!m) return null
  const [, base, realm] = m
  return { base, realm, tokenUrl, admin: `${base}/admin/realms/${realm}` }
}

const form = o => new URLSearchParams(o).toString()

const postForm = async (url, body) => {
  const r = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: form(body),
  })
  let data = null
  try { data = await r.json() } catch (e) { data = null }
  return { status: r.status, data }
}

const makeKeycloak = argv => {
  const ep = endpoints(argv)
  const wikiClient = { id: argv.oauth2_clientID || 'wiki', secret: argv.oauth2_clientSecret || '' }
  const adminClient = process.env.WIKI_LOGIN_CLIENT || 'wiki-login'
  const secretPath = process.env.WIKI_LOGIN_SECRET || DEFAULT_SECRET
  let cached = { token: null, exp: 0 }

  const readSecret = () => {
    try { return fs.readFileSync(secretPath, 'utf8').trim() } catch (e) { return '' }
  }

  // "Is this the current password?" — a password grant that we never keep.
  const verifyPassword = async (username, password) => {
    if (!ep) return { ok: false, reason: 'no-keycloak' }
    const { status, data } = await postForm(ep.tokenUrl, {
      grant_type: 'password', client_id: wikiClient.id, client_secret: wikiClient.secret,
      username, password, scope: 'openid',
    })
    if (status === 200 && data && data.access_token) return { ok: true }
    if (status === 401 || status === 400) return { ok: false, reason: 'wrong-password', detail: data && data.error }
    return { ok: false, reason: 'unreachable', detail: status }
  }

  const adminToken = async () => {
    const now = Date.now() / 1000
    if (cached.token && cached.exp - now > 30) return cached.token
    const secret = readSecret()
    if (!secret) throw new Error(`no service-account secret at ${secretPath}`)
    const { status, data } = await postForm(ep.tokenUrl, {
      grant_type: 'client_credentials', client_id: adminClient, client_secret: secret,
    })
    if (status !== 200 || !data || !data.access_token) throw new Error(`service account refused (${status})`)
    cached = { token: data.access_token, exp: now + (data.expires_in || 60) }
    return cached.token
  }

  const admin = async (method, p, body) => {
    const tok = await adminToken()
    const r = await fetch(`${ep.admin}${p}`, {
      method,
      headers: { Authorization: `Bearer ${tok}`, 'Content-Type': 'application/json', Accept: 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    })
    let data = null
    const text = await r.text()
    try { data = text ? JSON.parse(text) : null } catch (e) { data = text }
    return { status: r.status, data, location: r.headers.get('location') }
  }

  const findUser = async username => {
    const { status, data } = await admin('GET', `/users?username=${encodeURIComponent(username)}&exact=true`)
    if (status !== 200 || !Array.isArray(data)) throw new Error(`user lookup failed (${status})`)
    return data[0] || null
  }

  const resetPassword = async (username, next) => {
    const user = await findUser(username)
    if (!user) return { ok: false, reason: 'no-such-user' }
    const { status } = await admin('PUT', `/users/${user.id}/reset-password`,
      { type: 'password', value: next, temporary: false })
    return status === 204 ? { ok: true } : { ok: false, reason: 'reset-failed', detail: status }
  }

  // "username, Display Name[, email]" → a user with the common password, not
  // temporary (a temporary password would bounce the person to Keycloak's own
  // screen). Keycloak's user profile insists on an email before it will grant a
  // token ("Account is not fully set up"), so a missing one is synthesised under
  // the farm's own placeholder domain and marked verified.
  const placeholderDomain = process.env.WIKI_LOGIN_EMAIL_DOMAIN || 'login.invalid'
  const createUser = async ({ username, name, email }, password) => {
    const parts = (name || '').trim().split(/\s+/).filter(Boolean)
    const body = {
      username, enabled: true, emailVerified: true,
      email: email || `${username}@${placeholderDomain}`,
      firstName: parts[0] || username, lastName: parts.slice(1).join(' ') || '-',
      credentials: [{ type: 'password', value: password, temporary: false }],
      attributes: { source: ['wiki-plugin-login'] },
    }
    const { status, data } = await admin('POST', '/users', body)
    if (status === 201) return { username, result: 'created' }
    if (status === 409) return { username, result: 'exists' }
    return { username, result: 'failed', detail: (data && data.errorMessage) || status }
  }

  const deleteUser = async username => {
    const user = await findUser(username)
    if (!user) return { ok: false, reason: 'no-such-user' }
    const { status } = await admin('DELETE', `/users/${user.id}`)
    return status === 204 ? { ok: true } : { ok: false, detail: status }
  }

  return { endpoints: ep, secretPath, adminClient, verifyPassword, resetPassword, createUser, findUser, deleteUser }
}

const parseRoster = text => (text || '').split(/\r?\n/).map(l => l.trim()).filter(l => l && !l.startsWith('#'))
  .map(l => {
    const [username, name, email] = l.split(',').map(s => (s || '').trim())
    return { username: username.toLowerCase(), name, email: /^[^@\s]+@[^@\s]+$/.test(email || '') ? email : '' }
  })
  .filter(u => /^[a-z0-9][a-z0-9._-]{1,62}$/.test(u.username))

module.exports = { makeKeycloak, parseRoster, endpoints }
