# wiki-plugin-login

Easy Login for a Keycloak-backed Federated Wiki farm. One item type, `login`:

- `CHANGE` — a change-your-password form on a wiki page. The username is the
  session's login; the server proves the current password with the farm's own
  OAuth client (password grant), then resets it through a service account.
- `DESK` — owner only: paste `username, Display Name` lines and a common
  password; each becomes an enabled Keycloak user with a non-temporary
  password, so first login lands on the wiki rather than Keycloak's screens.

Routes: `GET /plugin/login/status`, `POST /plugin/login/change`,
`POST /plugin/login/desk` (JSON, same origin). Keycloak is derived from the
farm's `oauth2_TokenURL`; the service-account secret is read from
`~/.config/wiki-login/secret` (mode 600) or `$WIKI_LOGIN_SECRET`. The service
account (`wiki-login`, or `$WIKI_LOGIN_CLIENT`) needs realm-management
`view-users` + `manage-users` only. On a farm running `wiki-security-author`
(off-grid) the forms switch themselves off.

Build: `npm install && npm run build`. Live test against the real realm (creates
and deletes a throwaway user): `ssh host cat ~/.config/wiki-login/secret | npm run test:live`.
