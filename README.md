# tailscale-pushover-webhook

Simple Tailscale Webhook endpoint for broadcasting events via Pushover.

## Usage

```shell
$ pip3 install python-daemon
$ pip3 install python-dateutil

$ python3 app.py \
    --address=<address> \
    --port=<port> \
    --pushover-app-token=<app-token> \
    --pushover-user-key=<user-key>

$ sudo tailscale serve http://localhost:<port>
```
