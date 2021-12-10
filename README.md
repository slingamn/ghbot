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
# and GitHub will use it to sign its requests:
export GHBOT_GITHUB_SECRET_TOKEN=HyeVmUhQpADEvWuyLw5TDkpzeohjzw6RLKE6NPveuCk
# required: this should be used with nginx or similar for TLS termination:
export GHBOT_LISTEN_ADDR=unix:/tmp/ghbot_sock
# for proxying to loopback TCP:
# export GHBOT_LISTEN_ADDR="127.0.0.1:8080"
# for public plaintext HTTP (ugh):
# export GHBOT_LISTEN_ADDR=":9473"

# optional: for authenticating the bot to the IRC server
export GHBOT_SASL_LOGIN=ErgoBot
export GHBOT_SASL_PASSWORD=pLL2oLleAOg7AlD_MCoiMA
```

Here's a snippet of an nginx config for terminating TLS and forwarding to the bot's HTTP listener:

```nginx
        location /my_ghbot {
                proxy_pass http://unix:/tmp/ghbot_sock;
        }
```
