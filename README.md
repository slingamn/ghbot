ghbot
=====

ghbot is a simple IRC bot that receives GitHub events via [webhooks](https://docs.github.com/en/developers/webhooks-and-events/webhooks), then publishes them to an IRC channel.

It is configured using environment variables:

```bash
# required
export GHBOT_NICK=ErgoBot
export GHBOT_SERVER=testnet.ergo.chat:6697
export GHBOT_CHANNEL=#chat
# required: enter this in the GitHub webhook dashboard,
# and GitHub will use it to sign its requests.
# to generate a new, secure token:
# python3 -c "import secrets; print(secrets.token_urlsafe())"
export GHBOT_GITHUB_SECRET_TOKEN=HyeVmUhQpADEvWuyLw5TDkpzeohjzw6RLKE6NPveuCk
# required: this should be used with nginx or similar for TLS termination:
export GHBOT_LISTEN_ADDR=unix:/tmp/ghbot_sock
# for proxying to loopback TCP:
# export GHBOT_LISTEN_ADDR="127.0.0.1:8080"
# for a public listener:
# export GHBOT_LISTEN_ADDR=":9473"
# in which case you should set these for native TLS:
# export GHBOT_TLS_CERT_PATH="/path/to/cert.pem"
# export GHBOT_TLS_KEY_PATH="/path/to/key.pem"

# optional: for authenticating the bot to the IRC server
export GHBOT_SASL_LOGIN=ErgoBot
export GHBOT_SASL_PASSWORD=pLL2oLleAOg7AlD_MCoiMA
```

On the GitHub side, you must configure your webhook to send content type `application/json` (instead of the default `application/x-www-form-urlencoded`), and configure a secret token matching the value of `GHBOT_GITHUB_SECRET_TOKEN`.

Here's a snippet of an nginx config for terminating TLS and forwarding to the bot's HTTP listener:

```nginx
        location /my_ghbot {
                proxy_pass http://unix:/tmp/ghbot_sock;
        }
```

This bot should work with GitLab as well, but GitLab uses a static token for authentication instead of a signature system. Unset `GHBOT_GITHUB_SECRET_TOKEN` and instead export `GHBOT_GITLAB_SECRET_TOKEN`.
