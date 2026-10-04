"""Forward internal services to sandboxes, one granted method + path at a time.

Runs next to the proxy. For each service in the services file (see `grants`) it listens on
`listen` (e.g. proxy:11434) and forwards to the service's hidden `target`, but only requests
whose method + exact path are granted in the allowlist (`service:<name> <METHOD> <path>`
lines, added by the gatekeeper after the owner's 👍). Everything else gets 403 with a hint how
to request access.

- responses are streamed through as they arrive (Ollama streams tokens);
- deny-listed paths are refused even if granted;
- at most `max_concurrent` requests per service; a request waits up to 30 s for a slot, then 429;
- metadata only (service, method, path, status, duration, bytes) is logged, no bodies.

    python -m agent_mitm_proxy.forwarder

| Variable | Default | Meaning |
|---|---|---|
| FORWARDER_SERVICES | services.json | The services; missing: nothing to do |
| FORWARDER_ALLOWLIST | allowlist.txt | Where the grants are |
| FORWARDER_LOG | services.jsonl | Request metadata, as JSONL |
"""

import asyncio
import datetime
import json
import os
import pathlib
import time

import httpx
import uvicorn
from starlette.applications import Starlette
from starlette.background import BackgroundTask
from starlette.requests import Request
from starlette.responses import JSONResponse, StreamingResponse
from starlette.routing import Route

from .grants import METHODS, Service, denied, load_grants, load_services, normalize_path

HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te",
              "trailer", "transfer-encoding", "upgrade", "host", "content-length"}


class Grants:
    """The allowlist's service grants, reloaded when the file changes."""

    def __init__(self, path: pathlib.Path):
        self.path, self.stamp, self.grants = pathlib.Path(path), None, set()

    def get(self) -> set:
        try:
            st = self.path.stat()
        except FileNotFoundError:
            return set()
        stamp = (st.st_ino, st.st_size, st.st_mtime_ns)
        if stamp != self.stamp:
            self.grants, self.stamp = load_grants(self.path), stamp
        return self.grants


def append_log(path: pathlib.Path, record: dict) -> None:
    record["time"] = datetime.datetime.now(datetime.UTC).astimezone().isoformat(timespec="seconds")
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")


def make_app(service: Service, grants: Grants, log_path: pathlib.Path,
             transport: httpx.AsyncBaseTransport | None = None) -> Starlette:
    slots = asyncio.Semaphore(service.max_concurrent)
    client = httpx.AsyncClient(timeout=httpx.Timeout(service.timeout_s, connect=10),
                               trust_env=False, transport=transport)

    def log(record: dict) -> None:
        append_log(log_path, record)

    async def forward(request: Request):
        started = time.monotonic()
        method = request.method
        meta = {"service": service.name, "method": method, "path": request.url.path}

        def refuse(status: int, error: str, **extra):
            log({**meta, "status": status, "refused": error})
            return JSONResponse({"error": error, "service": service.name, "method": method,
                                 "path": request.url.path, **extra}, status_code=status)

        try:
            path = normalize_path(request.url.path)
        except ValueError as e:
            return refuse(400, str(e))
        meta["path"] = path
        if denied(service, path):
            return refuse(403, "this path is never allowed for this service")
        if (service.name, method, path) not in grants.get():
            return refuse(403, "not granted", hint=(
                f"Ask the owner with the MCP tool request_allowlist(service='{service.name}', "
                f"method='{method}', path='{path}', reason='...')"))

        body = await request.body()
        if len(body) > service.max_body:
            return refuse(413, f"request body larger than {service.max_body} bytes")
        try:
            await asyncio.wait_for(slots.acquire(), 30)
        except TimeoutError:
            return refuse(429, f"service busy (max {service.max_concurrent} concurrent requests)")

        url = service.target + path + (f"?{request.url.query}" if request.url.query else "")
        headers = {k: v for k, v in request.headers.items() if k.lower() not in HOP_BY_HOP}
        try:
            upstream = await client.send(client.build_request(method, url, headers=headers, content=body),
                                         stream=True)
        except httpx.HTTPError as e:
            slots.release()
            log({**meta, "status": 502, "error": type(e).__name__})
            return JSONResponse({"error": "service unavailable", "service": service.name}, status_code=502)

        sent = 0

        async def stream():
            nonlocal sent
            async for chunk in upstream.aiter_raw():
                sent += len(chunk)
                yield chunk

        async def done():
            await upstream.aclose()
            slots.release()
            log({**meta, "status": upstream.status_code, "bytes": sent,
                 "seconds": round(time.monotonic() - started, 2)})

        return StreamingResponse(
            stream(), status_code=upstream.status_code,
            headers={k: v for k, v in upstream.headers.items() if k.lower() not in HOP_BY_HOP},
            background=BackgroundTask(done))

    return Starlette(routes=[Route("/{rest:path}", forward, methods=[*METHODS, "OPTIONS"])])


async def main() -> None:
    services_path = pathlib.Path(os.environ.get("FORWARDER_SERVICES", "services.json"))
    grants = Grants(pathlib.Path(os.environ.get("FORWARDER_ALLOWLIST", "allowlist.txt")))
    log_path = pathlib.Path(os.environ.get("FORWARDER_LOG", "services.jsonl"))
    services = load_services(services_path)
    if not services:
        print(f"forwarder: no services in {services_path}; nothing to do", flush=True)
        return
    servers = [uvicorn.Server(uvicorn.Config(make_app(svc, grants, log_path), host="0.0.0.0",
                                             port=svc.listen, log_level="warning", access_log=False))
               for svc in services.values()]
    tasks = [asyncio.create_task(server.serve()) for server in servers]
    # Announce only once every port listens: start-forwarder.sh waits for these lines.
    while not all(server.started for server in servers) and not any(t.done() for t in tasks):
        await asyncio.sleep(0.05)
    if all(server.started for server in servers):
        for svc in services.values():
            print(f"forwarder: service {svc.name!r} on :{svc.listen}", flush=True)  # target not printed
    await asyncio.gather(*tasks)


if __name__ == "__main__":
    asyncio.run(main())
