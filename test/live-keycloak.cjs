// Live round-trip against the real realm with a throwaway user. Secrets arrive
// on stdin as two lines: the farm's `wiki` client secret, then the wiki-login
// service-account secret. Nothing is printed but outcomes.
//   { cat wiki-secret; ssh host cat ~/.config/wiki-login/secret; } | node test/live-keycloak.js
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const { makeKeycloak, parseRoster } = require('../server/keycloak.js')

const [wikiSecret, saSecret] = fs.readFileSync(0, 'utf8').split('\n').map(s => s.trim())
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'wl-'))
const secretFile = path.join(tmp, 'secret')
fs.writeFileSync(secretFile, saSecret, { mode: 0o600 })
process.env.WIKI_LOGIN_SECRET = secretFile

const argv = {
  oauth2_clientID: 'wiki', oauth2_clientSecret: wikiSecret,
  oauth2_TokenURL: 'https://auth.hitchhikers.earth/realms/wiki/protocol/openid-connect/token',
}
const kc = makeKeycloak(argv)
const user = `wl-test-${Date.now().toString(36)}`
const p1 = 'sprint-common-2026', p2 = 'my-own-key-2026'
const step = (name, ok, extra = '') => { console.log(`${ok ? 'PASS' : 'FAIL'} ${name} ${extra}`); if (!ok) process.exitCode = 1 }

;(async () => {
  try {
    const roster = parseRoster(`${user}, Test Person\n# comment\nBAD USER!, nope\n`)
    step('roster parses one valid line', roster.length === 1 && roster[0].username === user)
    const c = await kc.createUser(roster[0], p1)
    step('desk creates the user', c.result === 'created', JSON.stringify(c))
    const again = await kc.createUser(roster[0], p1)
    step('second create reports exists', again.result === 'exists')
    step('common password verifies', (await kc.verifyPassword(user, p1)).ok)
    step('wrong password refused', (await kc.verifyPassword(user, 'not-it-at-all')).reason === 'wrong-password')
    step('reset to own password', (await kc.resetPassword(user, p2)).ok)
    step('old password now refused', (await kc.verifyPassword(user, p1)).reason === 'wrong-password')
    step('new password verifies', (await kc.verifyPassword(user, p2)).ok)
    step('unknown user reset refused', (await kc.resetPassword('no-such-user-xyz', p2)).reason === 'no-such-user')
  } finally {
    const d = await kc.deleteUser(user).catch(e => ({ ok: false, detail: e.message }))
    step('throwaway user deleted', d.ok, d.ok ? '' : JSON.stringify(d))
    fs.rmSync(tmp, { recursive: true, force: true })
  }
})()
