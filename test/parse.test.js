import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
const require = createRequire(import.meta.url)
const { parseRoster, endpoints } = require('../server/keycloak.js')

test('roster: trims, lowercases, drops comments and bad names', () => {
  const r = parseRoster(' Anna , Anna Maria Sikorska\n# note\n\nbad name!, x\nsepp,Sepp E\n')
  assert.deepEqual(r, [{ username: 'anna', name: 'Anna Maria Sikorska', email: '' }, { username: 'sepp', name: 'Sepp E', email: '' }])
})

test('endpoints: base, realm and admin url from the farm token url', () => {
  const e = endpoints({ oauth2_TokenURL: 'https://auth.example.org/realms/wiki/protocol/openid-connect/token' })
  assert.equal(e.base, 'https://auth.example.org')
  assert.equal(e.realm, 'wiki')
  assert.equal(e.admin, 'https://auth.example.org/admin/realms/wiki')
  assert.equal(endpoints({}), null)
})
