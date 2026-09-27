#!/usr/bin/env python3
"""Generate or optionally send HTTP requests.

Generation is the default. Sending requires the explicit --send flag.
"""

from __future__ import annotations

import argparse
import json
import ipaddress
import shlex
import socket
import sys
import time
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode, urlparse, parse_qsl, urlunparse
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError


@dataclass
class RequestSpec:
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    params: dict[str, str] = field(default_factory=dict)
    body: Any | None = None
    blocked_ips: set[str] = field(default_factory=set)


def validate_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("URL must include http:// or https:// and a hostname")
    return url


def build_url(url: str, params: dict[str, str]) -> str:
    if not params:
        return url
    parsed = urlparse(url)
    existing = parse_qsl(parsed.query, keep_blank_values=True)
    query = urlencode(existing + list(params.items()))
    return urlunparse(parsed._replace(query=query))


def parse_pairs(values: list[str], label: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for value in values:
        if "=" not in value:
            raise ValueError(f"Each {label} must use KEY=VALUE: {value!r}")
        key, val = value.split("=", 1)
        if not key:
            raise ValueError(f"{label} key cannot be empty")
        result[key] = val
    return result


def validate_ip(value: str) -> str:
    """Validate and normalize an IPv4/IPv6 address for the blocklist."""
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise ValueError(f"Invalid IP address: {value!r}") from exc


def resolve_target_ips(url: str) -> set[str]:
    """Resolve the URL hostname to IP addresses before sending."""
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        raise ValueError("URL must include a hostname")
    try:
        results = socket.getaddrinfo(
            host, parsed.port or (443 if parsed.scheme == "https" else 80),
            type=socket.SOCK_STREAM
        )
    except socket.gaierror as exc:
        raise RuntimeError(f"Could not resolve {host}: {exc}") from exc
    return {str(ipaddress.ip_address(result[4][0])) for result in results if result[4]}


def enforce_ip_blocklist(url: str, blocked_ips: set[str]) -> None:
    """Refuse the request if the destination resolves to a blocked IP."""
    if not blocked_ips:
        return
    target_ips = resolve_target_ips(url)
    blocked = sorted(target_ips & blocked_ips)
    if blocked:
        raise RuntimeError(
            f"Request blocked: destination {url} resolves to blocked IP(s): {', '.join(blocked)}"
        )


def generate_curl(spec: RequestSpec) -> str:
    parts = ["curl", "-X", shlex.quote(spec.method), shlex.quote(spec.url)]
    for key, value in spec.headers.items():
        parts.extend(["-H", shlex.quote(f"{key}: {value}")])
    if spec.body is not None:
        body_text = json.dumps(spec.body, separators=(",", ":")) if not isinstance(spec.body, str) else spec.body
        parts.extend(["--data", shlex.quote(body_text)])
    return " \\\n  ".join(parts)


def python_literal(value: Any) -> str:
    return repr(value)


def generate_python(spec: RequestSpec) -> str:
    lines = ["import requests", "", f"url = {python_literal(spec.url)}"]
    if spec.params:
        lines.append(f"params = {python_literal(spec.params)}")
    if spec.headers:
        lines.append(f"headers = {python_literal(spec.headers)}")
    if spec.body is not None:
        if isinstance(spec.body, str):
            lines.append(f"data = {python_literal(spec.body)}")
        else:
            lines.append(f"json_data = {python_literal(spec.body)}")
    args = ["url"]
    if spec.params:
        args.append("params=params")
    if spec.headers:
        args.append("headers=headers")
    if spec.body is not None:
        args.append("data=data" if isinstance(spec.body, str) else "json=json_data")
    lines.extend(["", f"response = requests.{spec.method.lower()}({', '.join(args)})", "print(response.status_code)", "print(response.text)"])
    return "\n".join(lines)


def generate_raw(spec: RequestSpec) -> str:
    parsed = urlparse(spec.url)
    path = urlunparse(parsed._replace(scheme="", netloc="")) or "/"
    lines = [f"{spec.method} {path} HTTP/1.1", f"Host: {parsed.netloc}"]
    lines.extend(f"{key}: {value}" for key, value in spec.headers.items())
    if spec.body is not None:
        body_text = json.dumps(spec.body) if not isinstance(spec.body, str) else spec.body
        lines.append(f"Content-Length: {len(body_text.encode('utf-8'))}")
        lines.extend(["", body_text])
    return "\n".join(lines)


def parse_body(raw: str | None) -> Any | None:
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return raw


def send_request(spec: RequestSpec, timeout: float) -> tuple[int, str, dict[str, str]]:
    """Send one request and return status, response text, and response headers."""
    enforce_ip_blocklist(spec.url, spec.blocked_ips)
    if spec.body is None:
        payload = None
    elif isinstance(spec.body, str):
        payload = spec.body.encode("utf-8")
    else:
        payload = json.dumps(spec.body).encode("utf-8")

    headers = dict(spec.headers)
    if spec.body is not None and not any(key.lower() == "content-type" for key in headers):
        if not isinstance(spec.body, str):
            headers["Content-Type"] = "application/json"
    request = Request(spec.url, data=payload, headers=headers, method=spec.method)
    try:
        with urlopen(request, timeout=timeout) as response:
            return response.status, response.read().decode("utf-8", errors="replace"), dict(response.headers)
    except HTTPError as exc:
        # HTTP errors are still valid server responses; expose their status/body.
        return exc.code, exc.read().decode("utf-8", errors="replace"), dict(exc.headers)
    except URLError as exc:
        raise RuntimeError(f"Could not connect to {spec.url}: {exc.reason}") from exc


def interactive() -> RequestSpec:
    print("HTTP Request Generator")
    method = input("Method [GET]: ").strip().upper() or "GET"
    url = input("URL: ").strip()
    headers = parse_pairs([x.strip() for x in input("Headers KEY=VALUE (comma-separated, optional): ").split(",") if x.strip()], "header")
    params = parse_pairs([x.strip() for x in input("Query params KEY=VALUE (comma-separated, optional): ").split(",") if x.strip()], "parameter")
    body_raw = input("Body (JSON or text, optional): ").strip() or None
    blocked_raw = input("Blocked IPs (comma-separated, optional): ").strip()
    blocked_ips = {validate_ip(x) for x in blocked_raw.split(",") if x.strip()}
    return RequestSpec(method, build_url(validate_url(url), params), headers, params={}, body=parse_body(body_raw), blocked_ips=blocked_ips)



class LocalRequestHandler(BaseHTTPRequestHandler):
    """Local-only API wrapper around the existing request logic."""

    def _json_response(self, status: int, payload: dict[str, Any]) -> None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        if self.path == "/health":
            self._json_response(200, {"status": "ok"})
            return
        self._json_response(404, {"error": "not found"})

    def do_POST(self) -> None:
        if self.path != "/request":
            self._json_response(404, {"error": "not found"})
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length)
            payload = json.loads(raw.decode("utf-8"))

            method = str(payload.get("method", "GET")).upper()
            url = validate_url(str(payload["url"]))
            headers = payload.get("headers", {})
            if not isinstance(headers, dict):
                raise ValueError("headers must be an object")

            body = payload.get("body")
            blocked_ips = {
                validate_ip(str(value))
                for value in payload.get("blocked_ips", [])
            }
            timeout = float(payload.get("timeout", 30.0))
            if timeout <= 0:
                raise ValueError("timeout must be greater than zero")

            spec = RequestSpec(
                method=method,
                url=url,
                headers={str(k): str(v) for k, v in headers.items()},
                body=body,
                blocked_ips=blocked_ips,
            )

            if not spec.method.isalpha():
                raise ValueError("HTTP method must contain letters only")

            status, response_text, response_headers = send_request(spec, timeout)
            self._json_response(
                200,
                {
                    "status": status,
                    "headers": dict(response_headers),
                    "body": response_text,
                },
            )
        except (KeyError, TypeError, ValueError, OSError, RuntimeError, json.JSONDecodeError) as exc:
            self._json_response(400, {"error": str(exc)})

    def log_message(self, format: str, *args: Any) -> None:
        print(f"[PythonServer] {self.address_string()} - {format % args}")


def run_server(port: int) -> None:
    server = HTTPServer(("127.0.0.1", port), LocalRequestHandler)
    print(f"Python request server listening on http://127.0.0.1:{port}")
    print("Endpoints: GET /health, POST /request")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
    finally:
        server.server_close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate an HTTP request, or send it with explicit --send.")
    parser.add_argument("--url", help="Target URL, including http:// or https://")
    parser.add_argument("-X", "--method", default="GET", help="HTTP method (default: GET)")
    parser.add_argument("-H", "--header", action="append", default=[], metavar="KEY=VALUE", help="Request header; repeatable")
    parser.add_argument("-p", "--param", action="append", default=[], metavar="KEY=VALUE", help="Query parameter; repeatable")
    parser.add_argument("-d", "--data", help="Request body as JSON or plain text")
    parser.add_argument("--json", help="Request body from a JSON file")
    parser.add_argument("-f", "--format", choices=["curl", "python", "raw", "json"], default="curl", help="Output format (default: curl)")
    parser.add_argument("--send", action="store_true", help="Actually send the request instead of only generating it")
    parser.add_argument("--timeout", type=float, default=30.0, help="Send timeout in seconds (default: 30)")
    parser.add_argument("--repeat", type=int, default=1, help="Number of times to send the request (default: 1; requires --send)")
    parser.add_argument("--interval", type=float, default=0.0, help="Seconds to wait between repeated requests (default: 0)")
    parser.add_argument("--block-ip", action="append", default=[], metavar="IP", help="Block a destination IPv4/IPv6 address; repeatable")
    parser.add_argument("--server", action="store_true", help="Run the local-only HTTP API server")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8082")), help="Local server port (default: 8082)")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.server:
        if not (1 <= args.port <= 65535):
            parser.error("--port must be between 1 and 65535")
        run_server(args.port)
        return 0
    try:
        if not args.url:
            if any([args.header, args.param, args.data, args.json, args.block_ip]) or args.format != "curl" or args.send or args.repeat != 1 or args.interval != 0:
                parser.error("--url is required in non-interactive mode")
            spec = interactive()
        else:
            url = validate_url(args.url)
            params = parse_pairs(args.param, "parameter")
            headers = parse_pairs(args.header, "header")
            if args.data is not None and args.json:
                raise ValueError("Use either --data or --json, not both")
            body = parse_body(args.data)
            blocked_ips = {validate_ip(value) for value in args.block_ip}
            if args.json:
                with open(args.json, "r", encoding="utf-8") as handle:
                    body = json.load(handle)
            spec = RequestSpec(args.method.upper(), build_url(url, params), headers, params={}, body=body, blocked_ips=blocked_ips)

        if not spec.method.isalpha():
            raise ValueError("HTTP method must contain letters only")
        if args.timeout <= 0:
            raise ValueError("Timeout must be greater than zero")
        if args.repeat < 1:
            raise ValueError("--repeat must be at least 1")
        if args.interval < 0:
            raise ValueError("--interval cannot be negative")
        if args.repeat != 1 and not args.send:
            raise ValueError("--repeat requires --send")
        if args.send:
            exit_code = 0
            for attempt in range(1, args.repeat + 1):
                try:
                    status, response_text, response_headers = send_request(spec, args.timeout)
                    print(f"[{attempt}/{args.repeat}] HTTP {status}")
                    for key, value in response_headers.items():
                        print(f"{key}: {value}")
                    print()
                    print(response_text)
                    if not 200 <= status < 400:
                        exit_code = 1
                except RuntimeError as exc:
                    print(f"[{attempt}/{args.repeat}] Error: {exc}", file=sys.stderr)
                    exit_code = 2
                if attempt < args.repeat and args.interval:
                    time.sleep(args.interval)
            return exit_code
        if args.format == "curl":
            output = generate_curl(spec)
        elif args.format == "python":
            output = generate_python(spec)
        elif args.format == "raw":
            output = generate_raw(spec)
        else:
            output = json.dumps({"method": spec.method, "url": spec.url, "headers": spec.headers, "body": spec.body, "blocked_ips": sorted(spec.blocked_ips)}, indent=2)
        print(output)
        return 0
    except (ValueError, OSError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
