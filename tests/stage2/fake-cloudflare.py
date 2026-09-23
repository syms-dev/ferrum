#!/usr/bin/env python3
"""A stand-in Cloudflare v4 API, for tests/stage2/run.sh and nothing else.

Why this exists
---------------
The installer verifies the operator's Cloudflare token against the live API
before it erases anything (spec R1 A5). That check is deliberately
unskippable: an offline ferrum install produces a media server nobody can
reach, so a release valve added for a test would ship to every operator as
a way to get a silently broken host.

But stage 2 installs to ``s13.invalid``, which exists in nobody's Cloudflare
account, so no token can pass there -- not the placeholder the test feeds
it, and not a real credential either. Measured against the real API on
2026-09-23: ``placeholder-cf-token`` is refused with error 6003 (chain 6111,
"Invalid format for Authorization header") because Cloudflare rejects it on
shape before it ever checks validity, and a well-formed 40-character fake is
refused with 9109 "Invalid access token". The header ferrum sends is
correct; there is simply no zone to find.

So the test supplies something realistic instead of asking the product to
accept less. The installer built with the ``test-cloudflare-endpoint``
feature reads ``FERRUM_CLOUDFLARE_API_BASE`` and points its client here.
Everything else about the check runs unchanged -- the ``Authorization``
header, the ``success``-field inspection that HTTP status alone would miss,
pagination, longest-suffix zone resolution, the ``NS`` delegation listing
and the zone-status refusal.

Why not ferrum_dns::testing::FakeCloudflare
-------------------------------------------
That fake is a queue of scripted responses keyed by route: a test enqueues
exactly the answers it expects to be asked for, in order. It is the right
shape for a unit test and the wrong shape here, because a full installer run
makes a sequence of requests this script does not get to predict -- token
collection and the pre-erase dry run each resolve the zone, and pagination
means the count is a property of the responses rather than a constant.
Driving it as a standalone process would also need a new binary target in a
library crate that has none. A server that answers by rule rather than by
script is a few dozen lines, adds no dependency, and does not have to be
kept in step with the installer's call order.

What it serves
--------------
Only the routes the pre-erase path actually calls, which is
``Client::verify_zone_access`` -> ``resolve_zone``:

* ``GET /client/v4/zones`` -- one zone, named on the command line, status
  ``active`` so the gate does not refuse a zone Cloudflare will never serve.
* ``GET /client/v4/zones/<id>/dns_records`` -- empty, with and without
  ``type=NS``. An empty zone means no delegation away and no foreign record,
  so the gate asks the operator nothing and the scripted answers in
  ``run.sh`` stay in step.

Anything else is answered with Cloudflare's own "route not found" envelope
and logged loudly, because a silent 404 would surface three layers up as an
unreadable install failure.

Every request is logged to stderr with its method, path and query. That log
is the test's evidence that the installer really talked to this server: a
Cloudflare check that passes because nothing was asked would be
indistinguishable from one that passed correctly.

Usage
-----
    fake-cloudflare.py <port-file> <zone-name>

Binds loopback on an ephemeral port and writes the chosen port to
``<port-file>`` once it is listening, so the caller never races the bind and
never has to reserve a fixed port.
"""

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

#: Matches the real API's path, so the client's URL assembly is exercised
#: exactly as it is in production rather than against a bare host.
PREFIX = "/client/v4"

#: A fixed, obviously-fake zone id. Cloudflare's are 32 hex characters.
ZONE_ID = "ffffffffffffffffffffffffffffff13"

#: The zone's authoritative nameservers, as Cloudflare would report them.
#: Carried on the zone because post-apply verification queries these rather
#: than a recursive resolver; nothing in this test reaches that point, but
#: an absent list would make the zone look half-provisioned.
NAME_SERVERS = ["ns1.s13.invalid", "ns2.s13.invalid"]


def envelope(result, *, success=True, errors=(), pages=1):
    """Cloudflare's v4 response envelope.

    Args:
        result: the payload, already JSON-serializable.
        success: the body's own ``success`` field. ferrum checks this
            independently of the HTTP status, because Cloudflare answers
            several permission failures with HTTP 200 and ``success: false``.
        errors: an iterable of ``(code, message)`` pairs.
        pages: ``result_info.total_pages``; 1 ends the client's page walk.

    Returns:
        The envelope as UTF-8 encoded JSON bytes.
    """
    body = {
        "success": success,
        "errors": [{"code": code, "message": message} for code, message in errors],
        "messages": [],
        "result": result,
        "result_info": {"page": 1, "per_page": 100, "count": 0, "total_pages": pages},
    }
    return json.dumps(body).encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    """One request in, one ruled response out."""

    #: ureq keeps the connection alive; HTTP/1.0 would make it reconnect per
    #: request, which works but hides a whole class of framing mistake.
    protocol_version = "HTTP/1.1"

    #: Set from ``main`` -- the zone name this server claims to hold.
    zone_name = ""

    def log_message(self, fmt, *args):
        """Silences the default per-request line; ``do_GET`` logs instead."""

    def _send(self, status, payload):
        """Writes a status line, a JSON content type, and ``payload``."""
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):  # noqa: N802 -- the base class names it.
        """Answers the two listings ``resolve_zone`` performs."""
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        print(
            f"fake-cloudflare: GET {parsed.path} {parsed.query}",
            file=sys.stderr,
            flush=True,
        )

        # The token travels in this header and nowhere else, so this is the
        # one place to refuse an unauthenticated call. Refusing it matters:
        # the defect that made the whole DNS gate necessary was an empty
        # credential producing an empty plan that read as "nothing to do".
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer ") or not auth[len("Bearer ") :].strip():
            print("fake-cloudflare: refusing a request with no bearer token", file=sys.stderr, flush=True)
            self._send(400, envelope(None, success=False, errors=[(6003, "Invalid request headers")]))
            return

        if parsed.path == f"{PREFIX}/zones":
            self._send(
                200,
                envelope(
                    [
                        {
                            "id": ZONE_ID,
                            "name": self.zone_name,
                            "status": "active",
                            "name_servers": NAME_SERVERS,
                        }
                    ]
                ),
            )
            return

        # Both the ``type=NS`` delegation listing and the full record
        # listing land here. An empty zone is the whole point: ferrum then
        # owns every name it wants, so the gate has no foreign record to ask
        # the operator about and run.sh's scripted answers stay in step.
        if parsed.path == f"{PREFIX}/zones/{ZONE_ID}/dns_records":
            self._send(200, envelope([]))
            return

        print(
            f"fake-cloudflare: NO ROUTE for {parsed.path} (query {query}) -- "
            "the installer asked for something this server does not model",
            file=sys.stderr,
            flush=True,
        )
        self._send(404, envelope(None, success=False, errors=[(7003, "Could not route to that resource")]))


def main(argv):
    """Serves until killed.

    Args:
        argv: ``[port_file, zone_name]``.

    Returns:
        A process exit code; 2 when the arguments are wrong.
    """
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    port_file, zone_name = argv
    Handler.zone_name = zone_name

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    # Written only once the socket is listening, so the caller can wait for
    # this file rather than sleeping and hoping.
    with open(port_file, "w", encoding="utf-8") as handle:
        handle.write(str(port))
    print(
        f"fake-cloudflare: serving zone {zone_name} on http://127.0.0.1:{port}{PREFIX}",
        file=sys.stderr,
        flush=True,
    )
    server.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
