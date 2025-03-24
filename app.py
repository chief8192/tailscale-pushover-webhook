#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# MIT License

# Copyright (c) 2025 Matt Doyle

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import argparse
import daemon
import functools
import json
import os
import signal
import sys

from dateutil.parser import isoparse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from pushoverutil import Push


EXPECTED_EVENT_FIELDS = frozenset(
    [
        "data",
        "message",
        "tailnet",
        "timestamp",
        "type",
        "version",
    ]
)

VALID_EVENT_TYPES = frozenset(
    [
        "exitNodeIPForwardingNotEnabled",
        "nodeApproved",
        "nodeAuthorized",
        "nodeCreated",
        "nodeDeleted",
        "nodeKeyExpired",
        "nodeKeyExpiringInOneDay",
        "nodeNeedsApproval",
        "nodeNeedsAuthorization",
        "policyUpdate",
        "subnetIPForwardingNotEnabled",
        "test",
        "userApproved",
        "userCreated",
        "userNeedsApproval",
        "userRoleUpdated",
        "webhookDeleted",
        "webhookUpdated",
    ]
)


class WebhookHTTPServer(HTTPServer):

    def __init__(
        self,
        webhook_addr: str,
        webhook_port: int,
        pushover_app_token: str,
        pushover_user_key: str,
    ):

        request_handler = functools.partial(
            WebhookRequestHandler, pushover_app_token, pushover_user_key
        )

        print(f"Starting {self.__class__.__name__} on {webhook_addr}:{webhook_port}")
        super().__init__((webhook_addr, webhook_port), request_handler)


class WebhookRequestHandler(BaseHTTPRequestHandler):

    def __init__(
        self, pushover_app_token: str, pushover_user_key: str, *args, **kwargs
    ):
        self.pushover_app_token = pushover_app_token
        self.pushover_user_key = pushover_user_key
        super().__init__(*args, **kwargs)

    def do_POST(self):

        # Attempt to parse a JSON payload out of the POST body.
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            payload = json.loads(self.rfile.read(content_length))

        # If parsing fails, bail with a 400.
        except Exception as ex:
            print(f"Parsing error: {str(ex)}")
            self.send_response(HTTPStatus.BAD_REQUEST)
            self.end_headers()
            return

        # Tailscale will always send a list of events.
        if not isinstance(payload, list):
            print(f"Unexpected payload: {type(payload)}")
            self.send_response(HTTPStatus.BAD_REQUEST)
            self.end_headers()
            return

        print(f"Received {len(payload)} event{'' if len(payload) == 1 else 's'}")

        # Process each received event.
        for event in payload:

            actual_event_fields = set(event.keys())

            # Check for unexpected fields.
            unexpected_fields = list(actual_event_fields - EXPECTED_EVENT_FIELDS)
            if unexpected_fields:
                print(f"Unexpected fields: {unexpected_fields}")
                continue

            # Check for missing fields.
            missing_fields = list(EXPECTED_EVENT_FIELDS - actual_event_fields)
            if missing_fields:
                print(f"Missing fields: {missing_fields}")
                continue

            # Make sure the event type is supported.
            event_type = event.get("type")
            if event_type not in VALID_EVENT_TYPES:
                print(f"Unsupported event type: {event_type}")
                continue

            title = f"Tailscale: {event_type}"
            message = f"{event.get('message')}"

            # Print and send a push notification.
            print(f"Tailscale: {event_type} ({event.get('message')})")
            if self.pushover_user_key and self.pushover_app_token:
                Push(
                    self.pushover_user_key,
                    self.pushover_app_token,
                    message,
                    title=title,
                )

        self.send_response(HTTPStatus.OK)
        self.end_headers()


def main():

    # Load all the necessary config values from the environment.
    webhook_addr = os.environ.get("WEBHOOK_ADDR", "")
    webhook_port = os.environ.get("WEBHOOK_PORT", 443)
    pushover_app_token = os.environ.get("PUSHOVER_APP_TOKEN")
    pushover_user_key = os.environ.get("PUSHOVER_USER_KEY")

    if not pushover_app_token or not pushover_user_key:
        print("Error: Pushover credentials not provided")

    # Run the HTTPServer as a daemon.
    http_server = WebhookHTTPServer(
        webhook_addr,
        webhook_port,
        pushover_app_token,
        pushover_user_key,
    )
    daemon_context = daemon.DaemonContext()
    daemon_context.files_preserve = [http_server.fileno()]
    with daemon_context:
        http_server.serve_forever()


if __name__ == "__main__":
    main()
