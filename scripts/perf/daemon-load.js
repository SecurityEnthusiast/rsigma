// k6 load script for the daemon HTTP ingestion baseline.
//
// Posts fixed-size NDJSON batches from a fixture lane to POST /api/v1/events.
// Throughput is read from the daemon's own metrics (rsigma_events_processed_total),
// not from k6's request rate; see scripts/perf/baseline-daemon.sh.
//
// Environment:
//   LANE        path to an NDJSON lane file (required)
//   URL         ingest URL (default http://127.0.0.1:9090/api/v1/events)
//   BATCH       events per request (default 500)
//   VUS         concurrent clients (default 4)
//   DURATION    test duration (default 30s)

import http from "k6/http";
import { check } from "k6";

const lane = open(__ENV.LANE);
const batchSize = parseInt(__ENV.BATCH || "500", 10);
const url = __ENV.URL || "http://127.0.0.1:9090/api/v1/events";

const lines = lane.split("\n").filter((l) => l.length > 0);
const batches = [];
for (let i = 0; i < lines.length; i += batchSize) {
  batches.push(lines.slice(i, i + batchSize).join("\n"));
}

export const options = {
  vus: parseInt(__ENV.VUS || "4", 10),
  duration: __ENV.DURATION || "30s",
};

export default function () {
  const body = batches[Math.floor(Math.random() * batches.length)];
  const res = http.post(url, body, {
    headers: { "Content-Type": "application/x-ndjson" },
  });
  check(res, { "status 2xx": (r) => r.status >= 200 && r.status < 300 });
}
