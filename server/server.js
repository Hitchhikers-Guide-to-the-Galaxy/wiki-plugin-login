// wiki-plugin-login, server side — CommonJS (see sibling package.json).
//
// Routes (all under /plugin/login/, JSON in and out, same-origin only):
//   GET  status        who the session is, whether this farm can talk to
//                      Keycloak, whether the caller may use the desk
//   POST change        { current, next } — change the SESSION user's own
//                      password; the username comes from the login, never
//                      from the form
//   POST desk          { roster, password } — owner only: create each
//                      "username, Display Name" line with the common password
//
// Author security (the off-grid farm) has no Keycloak session: status says
// so in one sentence and the forms switch themselves off.

const { makeKeycloak, parseRoster } = require('./keycloak')

const VERSION = require('../package.json').version

const startServer = ({ argv, app }) => {
  const kc = makeKeycloak(argv)
  const sec = app.securityhandler || {}
  const log = (...a) => console.log('[login]', ...a)

  // Attempt limiter for the password check: 8 tries per address per 15 min.
  const attempts = new Map()
  const tooMany = ip => {
    const now = Date.now()
    const a = (attempts.get(ip) || []).filter(t => now - t < 15 * 60 * 1000)
    attempts.set(ip, a)
    return a.length >= 8
  }
  const noteAttempt = ip => attempts.set(ip, [...(attempts.get(ip) || []), Date.now()])

  // The Keycloak identity of this session, or null (anonymous / author farm).
  const sessionUser = req => {
    const u = typeof sec.getUser === 'function' ? sec.getUser(req) : ''
    if (!u || typeof u !== 'object') return null
    const o = u.oauth2 || u.github || u.twitter || null
    if (!o) return null
    return { username: o.username || o.id, name: o.displayName || o.username || o.id }
  }
  // wiki-server rewrites security_type to the resolved package name
  // (`author` → `wiki-security-author`), so match loosely.
  const mode = () => (/author/.test(argv.security_type || '') ? 'author' : kc.endpoints ? 'keycloak' : 'none')
  const isOwner = req => typeof sec.isAuthorized === 'function' && sec.isAuthorized(req)

  // No .json suffix: a login-to-view farm gates every *.json URL for anonymous
  // visitors, and the form needs to read its state before anyone logs in.
  app.get('/plugin/login/status', (req, res) => {
    const user = sessionUser(req)
    res.json({
      version: VERSION, mode: mode(), site: req.hostname,
      user: user ? user.username : null, name: user ? user.name : null,
      owner: mode() === 'keycloak' ? !!(user && isOwner(req)) : false,
      keycloak: kc.endpoints ? kc.endpoints.base : null,
    })
  })

  app.post('/plugin/login/change', async (req, res) => {
    const say = (status, message, extra) => res.status(status).json({ ok: status === 200, message, ...extra })
    if (mode() !== 'keycloak') return say(409, 'This wiki is off-grid: there is no login server to change a password on. Use the login-to-view wiki.')
    const user = sessionUser(req)
    if (!user) return say(401, 'Log in first. The password you change is the one for the login you are using now.')
    const { current, next } = req.body || {}
    if (typeof current !== 'string' || typeof next !== 'string') return say(400, 'Both passwords are needed.')
    if (next.length < 8) return say(400, 'The new password needs at least eight characters.')
    if (next === current) return say(400, 'The new password is the same as the current one.')
    const ip = req.ip || req.socket.remoteAddress
    if (tooMany(ip)) return say(429, 'Too many tries. Wait fifteen minutes and try again.')
    noteAttempt(ip)
    try {
      const v = await kc.verifyPassword(user.username, current)
      if (!v.ok && v.reason === 'wrong-password') return say(403, 'That is not your current password.')
      if (!v.ok) return say(502, 'The login server could not be reached. Nothing has changed.')
      const r = await kc.resetPassword(user.username, next)
      if (!r.ok) return say(502, `The login server refused the change (${r.reason}). Your old password still works.`)
      log(`password changed for ${user.username} on ${req.hostname}`)
      return say(200, 'Done. Your new password works from now on, on every wiki that asks for this login.')
    } catch (e) {
      log('change failed:', e.message)
      return say(502, 'The login server could not be reached. Nothing has changed.')
    }
  })

  app.post('/plugin/login/desk', async (req, res) => {
    const say = (status, message, extra) => res.status(status).json({ ok: status === 200, message, ...extra })
    if (mode() !== 'keycloak') return say(409, 'The desk needs the login server; this wiki is off-grid.')
    const user = sessionUser(req)
    if (!user || !isOwner(req)) return say(403, 'The desk is for the owner of this wiki.')
    const { roster, password } = req.body || {}
    const users = parseRoster(roster)
    if (!users.length) return say(400, 'No usable lines. One per line: username, Display Name')
    if (typeof password !== 'string' || password.length < 8) return say(400, 'The common password needs at least eight characters.')
    const results = []
    try {
      for (const u of users) results.push(await kc.createUser(u, password))
    } catch (e) {
      log('desk failed:', e.message)
      return say(502, 'The login server could not be reached.', { results })
    }
    const created = results.filter(r => r.result === 'created').map(r => r.username)
    log(`desk by ${user.username} on ${req.hostname}: ${results.map(r => `${r.username}=${r.result}`).join(' ')}`)
    return say(200, `${created.length} created, ${results.length - created.length} skipped.`, { results, created })
  })

  log(`v${VERSION} ready for ${argv.wiki || 'farm'} — mode ${mode()}, admin client ${kc.adminClient}`)
}

module.exports = { startServer }
