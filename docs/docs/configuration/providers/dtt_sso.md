---
id: dtt_sso
title: DTT SSO
---

Signs users in with the DTT SSO (auth-server) using the authorization code flow and its HS256 id_token.

1.  Register a client in the auth-server config, one per protected service, with the proxy's callback as its
    only redirect URI:

    ```yaml
    clients:
      redash-gate:
        secret: <random secret>
        redirect_uri: https://redash.example.com/oauth2/callback
        display_name: Redash
    ```

2.  Run the proxy with:

    ```shell
        --provider=dtt-sso
        --client-id=redash-gate
        --client-secret-file=/run/secrets/client_secret
        --redirect-url=https://redash.example.com/oauth2/callback
        --cookie-secret-file=/run/secrets/cookie_secret
        --cookie-name=_dtt_sso_redash
        --cookie-refresh=5m
    ```

    Give each instance its own `--cookie-name`: another oauth2-proxy setting its cookie on a parent domain
    (the Atlassian proxy uses `_oauth2_proxy` on `.thebestagent.pro`) would otherwise shadow this one.

The endpoints default to `https://auth.thebestagent.pro`. For another SSO host set `--login-url`, `--redeem-url`
and `--validate-url` to its `/oauth/authorize`, `/oauth/token` and `/oauth/check_token`; the id_token issuer must
equal the login URL's origin (the SSO's `site_host`).

The scope must stay `openid`, the only scope the SSO accepts.

The session carries the SSO `email`, the user UUID as the user, and the SSO `role` as the only group, so
`--allowed-group=dtt_admin` restricts access by role. `--authenticated-emails-file` and `--email-domain` restrict
by email as usual.

With `--cookie-refresh` set, the proxy refreshes the tokens on that interval and re-reads the email and role; a user
deleted or signed out in the SSO loses access at the next refresh.
