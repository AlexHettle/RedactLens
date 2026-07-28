import assert from "node:assert/strict";
import test from "node:test";

import {
  unexpectedBrowserLogErrors,
  unexpectedNetworkFailures,
} from "./e2e_phase9_browser_errors.mjs";

const expectedDeniedResponses = [
  { status: 404, pathname: "/scans/scan-1/open-file" },
  { status: 422, pathname: "/scans/scan-1/open-output" },
];

const responses = [
  {
    requestId: "expected-404",
    status: 404,
    url: "http://127.0.0.1:8000/scans/scan-1/open-file",
  },
  {
    requestId: "expected-422",
    status: 422,
    url: "http://127.0.0.1:8000/scans/scan-1/open-output",
  },
  {
    requestId: "unexpected-path",
    status: 404,
    url: "http://127.0.0.1:8000/redactlens-mark.svg",
  },
  {
    requestId: "unexpected-status",
    status: 500,
    url: "http://127.0.0.1:8000/scans/scan-1/open-file",
  },
];

test("filters network logs for the exact expected denied requests", () => {
  const expectedLogs = [
    {
      source: "network",
      text: "expected 404 browser log",
      networkRequestId: "expected-404",
    },
    {
      source: "network",
      text: "expected 422 browser log",
      networkRequestId: "expected-422",
    },
  ];

  assert.deepEqual(
    unexpectedBrowserLogErrors(
      expectedLogs,
      responses,
      expectedDeniedResponses,
    ),
    [],
  );
});

test("retains every uncorrelated or non-network browser log error", () => {
  const unexpectedLogs = [
    {
      source: "javascript",
      text: "script exception",
      networkRequestId: "expected-404",
    },
    {
      source: "network",
      text: "unknown request",
      networkRequestId: "unknown-request",
    },
    {
      source: "network",
      text: "missing request identity",
      networkRequestId: null,
    },
    {
      source: "network",
      text: "unexpected asset failure",
      networkRequestId: "unexpected-path",
    },
    {
      source: "network",
      text: "unexpected server failure",
      networkRequestId: "unexpected-status",
    },
  ];

  assert.deepEqual(
    unexpectedBrowserLogErrors(
      unexpectedLogs,
      responses,
      expectedDeniedResponses,
    ),
    unexpectedLogs,
  );
});

test("filters only completed request cancellations owned by UI transitions", () => {
  const requests = [
    {
      requestId: "delete-scan",
      method: "DELETE",
      url: "http://127.0.0.1:8000/scans/scan-1",
    },
    {
      requestId: "event-stream",
      method: "GET",
      url: "http://127.0.0.1:8000/scans/scan-2/events?after=0",
    },
    {
      requestId: "appearance-theme",
      method: "PUT",
      url: "http://127.0.0.1:8000/appearance/theme",
    },
  ];
  const responses = [
    {
      requestId: "delete-scan",
      status: 204,
      url: "http://127.0.0.1:8000/scans/scan-1",
    },
    {
      requestId: "event-stream",
      status: 200,
      url: "http://127.0.0.1:8000/scans/scan-2/events?after=0",
    },
    {
      requestId: "appearance-theme",
      status: 204,
      url: "http://127.0.0.1:8000/appearance/theme",
    },
  ];
  const expectedCancellations = [
    {
      requestId: "delete-scan",
      errorText: "net::ERR_ABORTED",
      canceled: true,
      blockedReason: null,
    },
    {
      requestId: "event-stream",
      errorText: "net::ERR_ABORTED",
      canceled: true,
      blockedReason: null,
    },
    {
      requestId: "appearance-theme",
      errorText: "net::ERR_ABORTED",
      canceled: true,
      blockedReason: null,
    },
  ];

  assert.deepEqual(
    unexpectedNetworkFailures(expectedCancellations, requests, responses),
    [],
  );
});

test("retains unknown, blocked, and incomplete transport failures", () => {
  const requests = [
    {
      requestId: "asset",
      method: "GET",
      url: "http://127.0.0.1:8000/assets/app.js",
    },
    {
      requestId: "failed-delete",
      method: "DELETE",
      url: "http://127.0.0.1:8000/scans/scan-1",
    },
  ];
  const responses = [
    {
      requestId: "failed-delete",
      status: 500,
      url: "http://127.0.0.1:8000/scans/scan-1",
    },
  ];
  const unexpectedFailures = [
    {
      requestId: "asset",
      errorText: "net::ERR_ABORTED",
      canceled: true,
      blockedReason: null,
    },
    {
      requestId: "failed-delete",
      errorText: "net::ERR_ABORTED",
      canceled: true,
      blockedReason: null,
    },
    {
      requestId: "unknown",
      errorText: "net::ERR_BLOCKED_BY_CLIENT",
      canceled: false,
      blockedReason: "inspector",
    },
  ];

  assert.deepEqual(
    unexpectedNetworkFailures(unexpectedFailures, requests, responses),
    unexpectedFailures,
  );
});
