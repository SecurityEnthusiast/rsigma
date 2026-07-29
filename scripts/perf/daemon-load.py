#!/usr/bin/env python3
"""Standard-library HTTP load driver for the daemon performance harness."""

import http.client
import os
import random
import sys
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit


def duration_seconds(value):
    if value.endswith("ms"):
        return float(value[:-2]) / 1000
    if value.endswith("s"):
        return float(value[:-1])
    if value.endswith("m"):
        return float(value[:-1]) * 60
    return float(value)


def main():
    lane = os.environ.get("LANE")
    if not lane:
        raise SystemExit("LANE is required")

    url = urlsplit(os.environ.get("URL", "http://127.0.0.1:9090/api/v1/events"))
    if url.scheme != "http":
        raise SystemExit("daemon-load.py supports http URLs only")

    batch_size = int(os.environ.get("BATCH", "500"))
    workers = int(os.environ.get("VUS", "4"))
    duration = duration_seconds(os.environ.get("DURATION", "30s"))
    lines = [line for line in Path(lane).read_bytes().splitlines() if line]
    batches = [b"\n".join(lines[i : i + batch_size]) for i in range(0, len(lines), batch_size)]
    if not batches:
        raise SystemExit(f"lane is empty: {lane}")

    deadline = time.monotonic() + duration
    requests = 0
    failures = []
    lock = threading.Lock()

    def drive(worker_id):
        nonlocal requests
        rng = random.Random(worker_id)
        connection = http.client.HTTPConnection(url.hostname, url.port or 80, timeout=30)
        local_requests = 0
        try:
            while time.monotonic() < deadline:
                body = batches[rng.randrange(len(batches))]
                connection.request(
                    "POST",
                    url.path,
                    body=body,
                    headers={"Content-Type": "application/x-ndjson"},
                )
                response = connection.getresponse()
                response.read()
                if not 200 <= response.status < 300:
                    raise RuntimeError(f"HTTP {response.status}")
                local_requests += 1
        except Exception as exc:
            with lock:
                failures.append(f"worker {worker_id}: {exc}")
        finally:
            connection.close()
            with lock:
                requests += local_requests

    threads = [threading.Thread(target=drive, args=(i,), daemon=True) for i in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    print(f"requests={requests} workers={workers} duration_s={duration:g}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
