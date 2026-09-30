---
id: atlassian
title: Atlassian Cloud
---

1.  Create an OAuth 2.0 integration in the [Atlassian developer console](https://developer.atlassian.com/console/myapps/).
2.  Under **Permissions**, add the User identity API with the `read:me` scope.
3.  Under **Authorization**, set the callback URL to `https://<proxy_host>/oauth2/callback`.
4.  Copy the client ID and secret from **Settings**.
5.  Run the proxy with:

```shell
    --provider=atlassian
    --client-id=<client ID>
    --client-secret=<secret>
    --redirect-url=https://<proxy_host>/oauth2/callback
    --cookie-secret=<cookie secret>
```

A new app works only for the account that created it. Enable sharing under **Distribution** to let other users sign in.
Atlassian then admits only accounts with access to the Atlassian site the app is installed on; others are refused at
the consent screen.

The proxy reads the user's email from `https://api.atlassian.com/me`. Restricting access further is supported by
[email](index.md#email-authentication). With `--cookie-refresh` set, the proxy re-validates the token against `/me` on
that interval.
