import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { TextDecoder } from "node:util";

import {
  unexpectedBrowserLogErrors,
  unexpectedNetworkFailures,
} from "./e2e_phase9_browser_errors.mjs";

const [webSocketUrl, appUrl, targetPath, downloadPath] = process.argv.slice(2);
if (![webSocketUrl, appUrl, targetPath, downloadPath].every(Boolean)) {
  throw new Error(
    "Expected DevTools URL, app URL, target path, and download path.",
  );
}

const POLL_MS = 100;
const DEFAULT_TIMEOUT_MS = 30_000;
const WEB_SOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const MAX_MESSAGE_BYTES = 64 * 1024 * 1024;
const SOCKET_CONNECTING = 0;
const SOCKET_OPEN = 1;
const SOCKET_CLOSING = 2;
const SOCKET_CLOSED = 3;

function safeEndpointLabel(url) {
  try {
    const endpoint = new URL(url);
    return `${endpoint.protocol}//${endpoint.host}`;
  } catch {
    return "the configured endpoint";
  }
}

class DevToolsWebSocket {
  constructor(url) {
    let endpoint;
    try {
      endpoint = new URL(url);
    } catch {
      throw new Error("The browser returned an invalid DevTools endpoint.");
    }
    if (endpoint.protocol !== "ws:") {
      throw new Error(
        "The DevTools endpoint must use an unencrypted ws:// URL.",
      );
    }
    if (endpoint.username || endpoint.password || endpoint.hash) {
      throw new Error("The DevTools endpoint contains unsupported URL fields.");
    }

    this.endpoint = endpoint;
    this.endpointLabel = safeEndpointLabel(endpoint);
    this.readyState = SOCKET_CONNECTING;
    this.socket = null;
    this.incoming = Buffer.alloc(0);
    this.fragmentOpcode = null;
    this.fragments = [];
    this.fragmentBytes = 0;
    this.messageListeners = [];
    this.errorListeners = [];
    this.closeListeners = [];
    this.errorNotified = false;
    this.closeNotified = false;
    this.closeTimer = null;
  }

  onMessage(listener) {
    this.messageListeners.push(listener);
  }

  onError(listener) {
    this.errorListeners.push(listener);
  }

  onClose(listener) {
    this.closeListeners.push(listener);
  }

  connect(timeoutMs = 10_000) {
    if (this.readyState !== SOCKET_CONNECTING) {
      return Promise.reject(
        new Error("The DevTools WebSocket connection has already been used."),
      );
    }

    return new Promise((resolve, reject) => {
      const key = crypto.randomBytes(16).toString("base64");
      const expectedAccept = crypto
        .createHash("sha1")
        .update(key + WEB_SOCKET_GUID, "ascii")
        .digest("base64");
      let settled = false;
      let handshake = Buffer.alloc(0);
      const timer = setTimeout(() => {
        this.socket?.destroy(
          new Error("Timed out waiting for the HTTP Upgrade response."),
        );
      }, timeoutMs);

      const fail = (error) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        this.readyState = SOCKET_CLOSED;
        this.socket?.destroy();
        reject(
          new Error(
            `Could not connect to the browser DevTools endpoint at ${this.endpointLabel}: ${error.message}`,
          ),
        );
      };

      const hostname = this.endpoint.hostname.replace(/^\[(.*)]$/, "$1");
      const port = Number(this.endpoint.port || 80);
      this.socket = net.createConnection({ host: hostname, port });
      this.socket.once("connect", () => {
        const requestTarget = `${this.endpoint.pathname}${this.endpoint.search}`;
        this.socket.write(
          `GET ${requestTarget} HTTP/1.1\r\n` +
            `Host: ${this.endpoint.host}\r\n` +
            "Upgrade: websocket\r\n" +
            "Connection: Upgrade\r\n" +
            `Sec-WebSocket-Key: ${key}\r\n` +
            "Sec-WebSocket-Version: 13\r\n\r\n",
          "ascii",
        );
      });
      const handleHandshake = (chunk) => {
        handshake = handshake.length
          ? Buffer.concat([handshake, chunk])
          : chunk;
        if (handshake.length > 16 * 1024) {
          fail(new Error("the HTTP Upgrade response headers were too large"));
          return;
        }
        const headerEnd = handshake.indexOf("\r\n\r\n");
        if (headerEnd === -1) return;

        const headerText = handshake.subarray(0, headerEnd).toString("latin1");
        const head = handshake.subarray(headerEnd + 4);
        let response;
        try {
          response = this.#parseUpgrade(headerText);
          this.#validateUpgrade(
            response.statusCode,
            response.headers,
            expectedAccept,
          );
        } catch (error) {
          fail(error);
          return;
        }

        if (settled) {
          this.socket.destroy();
          return;
        }
        settled = true;
        clearTimeout(timer);
        this.readyState = SOCKET_OPEN;
        this.socket.setNoDelay(true);
        this.socket.off("data", handleHandshake);
        this.socket.on("data", (data) => this.#consume(data));
        resolve();
        if (head.length) this.#consume(head);
      };
      this.socket.on("data", handleHandshake);
      this.socket.once("error", (error) => {
        if (!settled) fail(error);
        else this.#transportError(error);
      });
      this.socket.once("end", () => {
        if (!settled)
          fail(new Error("the connection ended before the HTTP Upgrade"));
        else this.#finishClose();
      });
      this.socket.once("close", () => {
        if (!settled)
          fail(new Error("the connection closed before the HTTP Upgrade"));
        else this.#finishClose();
      });
    });
  }

  #parseUpgrade(headerText) {
    const lines = headerText.split("\r\n");
    const status = /^HTTP\/1\.[01] (\d{3})(?: |$)/.exec(lines.shift() ?? "");
    if (!status) throw new Error("the HTTP Upgrade status line was invalid");
    const headers = {};
    for (const line of lines) {
      if (/^[ \t]/.test(line)) {
        throw new Error("the HTTP Upgrade response used folded headers");
      }
      const separator = line.indexOf(":");
      if (separator <= 0) {
        throw new Error(
          "the HTTP Upgrade response contained an invalid header",
        );
      }
      const name = line.slice(0, separator).trim().toLowerCase();
      if (!/^[!#$%&'*+.^_`|~0-9a-z-]+$/.test(name)) {
        throw new Error(
          "the HTTP Upgrade response contained an invalid header name",
        );
      }
      const value = line.slice(separator + 1).trim();
      if (/[\0-\x08\x0a-\x1f\x7f]/.test(value)) {
        throw new Error(
          "the HTTP Upgrade response contained an invalid header value",
        );
      }
      headers[name] = headers[name] ? `${headers[name]}, ${value}` : value;
    }
    return { statusCode: Number(status[1]), headers };
  }

  #validateUpgrade(statusCode, headers, expectedAccept) {
    if (statusCode !== 101) {
      throw new Error(`the server returned HTTP ${statusCode} instead of 101`);
    }
    if (headers.upgrade?.toLowerCase() !== "websocket") {
      throw new Error("the HTTP Upgrade header was not websocket");
    }
    const connectionTokens = String(headers.connection ?? "")
      .split(",")
      .map((value) => value.trim().toLowerCase());
    if (!connectionTokens.includes("upgrade")) {
      throw new Error("the HTTP Connection header did not confirm the upgrade");
    }
    const actualAccept = headers["sec-websocket-accept"];
    const actual = Buffer.from(String(actualAccept ?? ""), "ascii");
    const expected = Buffer.from(expectedAccept, "ascii");
    if (
      actual.length !== expected.length ||
      !crypto.timingSafeEqual(actual, expected)
    ) {
      throw new Error("the Sec-WebSocket-Accept value was invalid");
    }
    if (
      headers["sec-websocket-extensions"] ||
      headers["sec-websocket-protocol"]
    ) {
      throw new Error(
        "the server selected an extension or protocol not offered",
      );
    }
  }

  sendText(text) {
    if (this.readyState !== SOCKET_OPEN) {
      throw new Error("The DevTools WebSocket is not open.");
    }
    const payload = Buffer.from(text, "utf8");
    if (payload.length > MAX_MESSAGE_BYTES) {
      throw new Error("The DevTools message exceeded the 64 MiB safety limit.");
    }
    this.#writeFrame(0x1, payload);
  }

  close(code = 1000) {
    if (this.readyState === SOCKET_CONNECTING) {
      this.readyState = SOCKET_CLOSED;
      this.socket?.destroy();
      this.#finishClose();
      return;
    }
    if (this.readyState !== SOCKET_OPEN) return;
    const payload = Buffer.allocUnsafe(2);
    payload.writeUInt16BE(code);
    this.readyState = SOCKET_CLOSING;
    this.#writeFrame(0x8, payload, true);
    this.#startCloseTimer();
  }

  #writeFrame(opcode, payload, allowClosing = false) {
    if (
      !this.socket ||
      (this.readyState !== SOCKET_OPEN &&
        !(allowClosing && this.readyState === SOCKET_CLOSING))
    ) {
      throw new Error("The DevTools WebSocket is not writable.");
    }
    const frame = this.#encodeFrame(opcode, payload);
    this.socket.write(frame, (error) => {
      if (error) this.#transportError(error);
    });
  }

  #encodeFrame(opcode, payload) {
    let headerLength = 2;
    if (payload.length >= 126 && payload.length <= 0xffff) headerLength += 2;
    else if (payload.length > 0xffff) headerLength += 8;

    const mask = crypto.randomBytes(4);
    const frame = Buffer.allocUnsafe(
      headerLength + mask.length + payload.length,
    );
    frame[0] = 0x80 | opcode;
    if (payload.length < 126) {
      frame[1] = 0x80 | payload.length;
    } else if (payload.length <= 0xffff) {
      frame[1] = 0x80 | 126;
      frame.writeUInt16BE(payload.length, 2);
    } else {
      frame[1] = 0x80 | 127;
      frame.writeBigUInt64BE(BigInt(payload.length), 2);
    }
    mask.copy(frame, headerLength);
    const payloadOffset = headerLength + mask.length;
    for (let index = 0; index < payload.length; index += 1) {
      frame[payloadOffset + index] = payload[index] ^ mask[index % 4];
    }
    return frame;
  }

  #consume(chunk) {
    if (this.readyState === SOCKET_CLOSED) return;
    this.incoming = this.incoming.length
      ? Buffer.concat([this.incoming, chunk])
      : chunk;
    let cursor = 0;

    try {
      while (this.incoming.length - cursor >= 2) {
        const first = this.incoming[cursor];
        const second = this.incoming[cursor + 1];
        const final = Boolean(first & 0x80);
        const opcode = first & 0x0f;
        const isControl = opcode >= 0x8;
        if (first & 0x70) throw new Error("reserved frame bits were set");
        if (second & 0x80) throw new Error("the server sent a masked frame");

        let headerLength = 2;
        const lengthCode = second & 0x7f;
        let payloadLength = lengthCode;
        if (lengthCode === 126) {
          if (this.incoming.length - cursor < 4) break;
          payloadLength = this.incoming.readUInt16BE(cursor + 2);
          if (payloadLength < 126) {
            throw new Error("a frame used a non-minimal payload length");
          }
          headerLength = 4;
        } else if (lengthCode === 127) {
          if (this.incoming.length - cursor < 10) break;
          const largeLength = this.incoming.readBigUInt64BE(cursor + 2);
          if (largeLength <= 0xffffn) {
            throw new Error("a frame used a non-minimal payload length");
          }
          if (largeLength > BigInt(Number.MAX_SAFE_INTEGER)) {
            throw new Error("a frame length exceeded the safe integer range");
          }
          payloadLength = Number(largeLength);
          headerLength = 10;
        }
        if (isControl && (!final || payloadLength > 125)) {
          throw new Error("a control frame was fragmented or too large");
        }
        if (payloadLength > MAX_MESSAGE_BYTES) {
          throw new Error("a frame exceeded the 64 MiB safety limit");
        }

        const frameEnd = cursor + headerLength + payloadLength;
        if (this.incoming.length < frameEnd) break;
        const payload = this.incoming.subarray(cursor + headerLength, frameEnd);
        cursor = frameEnd;
        this.#handleFrame(opcode, final, payload);
        if (this.readyState === SOCKET_CLOSED) break;
      }
      this.incoming = this.incoming.subarray(cursor);
    } catch (error) {
      this.incoming = Buffer.alloc(0);
      this.#protocolError(error.message);
    }
  }

  #handleFrame(opcode, final, payload) {
    if (opcode === 0x0) {
      if (this.fragmentOpcode === null) {
        throw new Error("a continuation frame had no initial frame");
      }
      this.#appendFragment(payload);
      if (final) this.#finishFragments();
      return;
    }
    if (opcode === 0x1) {
      if (this.fragmentOpcode !== null) {
        throw new Error("a new data frame interrupted a fragmented message");
      }
      if (final) this.#emitText(payload);
      else {
        this.fragmentOpcode = opcode;
        this.#appendFragment(payload);
      }
      return;
    }
    if (opcode === 0x2) {
      throw new Error("the server sent an unsupported binary message");
    }
    if (opcode === 0x8) {
      this.#handleClose(payload);
      return;
    }
    if (opcode === 0x9) {
      this.#writeFrame(0x0a, payload, true);
      return;
    }
    if (opcode === 0x0a) return;
    throw new Error(`the server sent unknown opcode ${opcode}`);
  }

  #appendFragment(payload) {
    this.fragmentBytes += payload.length;
    if (this.fragmentBytes > MAX_MESSAGE_BYTES) {
      throw new Error("a fragmented message exceeded the 64 MiB safety limit");
    }
    this.fragments.push(payload);
  }

  #finishFragments() {
    const opcode = this.fragmentOpcode;
    const payload = Buffer.concat(this.fragments, this.fragmentBytes);
    this.fragmentOpcode = null;
    this.fragments = [];
    this.fragmentBytes = 0;
    if (opcode !== 0x1) {
      throw new Error("the fragmented message was not text");
    }
    this.#emitText(payload);
  }

  #emitText(payload) {
    let text;
    try {
      text = new TextDecoder("utf-8", { fatal: true }).decode(payload);
    } catch {
      throw new Error("a text message was not valid UTF-8");
    }
    for (const listener of this.messageListeners) {
      try {
        listener(text);
      } catch {
        throw new Error("a DevTools message could not be processed");
      }
    }
  }

  #handleClose(payload) {
    if (payload.length === 1) {
      throw new Error("a close frame contained an incomplete status code");
    }
    if (payload.length >= 2) {
      const code = payload.readUInt16BE(0);
      const validCode =
        (code >= 1000 && code <= 1014 && ![1004, 1005, 1006].includes(code)) ||
        (code >= 3000 && code <= 4999);
      if (!validCode)
        throw new Error("a close frame had an invalid status code");
      try {
        new TextDecoder("utf-8", { fatal: true }).decode(payload.subarray(2));
      } catch {
        throw new Error("a close frame reason was not valid UTF-8");
      }
    }

    if (this.readyState === SOCKET_OPEN) {
      this.readyState = SOCKET_CLOSING;
      this.#writeFrame(0x8, payload, true);
    }
    this.socket?.end();
    this.#startCloseTimer();
  }

  #protocolError(detail) {
    if (this.readyState === SOCKET_CLOSED) return;
    this.#notifyError(new Error(`Invalid DevTools WebSocket data: ${detail}.`));
    if (this.socket && this.readyState === SOCKET_OPEN) {
      const payload = Buffer.allocUnsafe(2);
      payload.writeUInt16BE(1002);
      this.readyState = SOCKET_CLOSING;
      this.socket.end(this.#encodeFrame(0x8, payload));
      this.#startCloseTimer();
    } else {
      this.socket?.destroy();
      this.#finishClose();
    }
  }

  #transportError(error) {
    if (this.readyState === SOCKET_CLOSED) return;
    this.#notifyError(
      new Error(`DevTools WebSocket transport error: ${error.message}`),
    );
    this.socket?.destroy();
    this.#finishClose();
  }

  #notifyError(error) {
    if (this.errorNotified) return;
    this.errorNotified = true;
    for (const listener of this.errorListeners) listener(error);
  }

  #startCloseTimer() {
    if (this.closeTimer) return;
    this.closeTimer = setTimeout(() => this.socket?.destroy(), 1_000);
    this.closeTimer.unref?.();
  }

  #finishClose() {
    if (this.closeNotified) return;
    this.closeNotified = true;
    this.readyState = SOCKET_CLOSED;
    if (this.closeTimer) clearTimeout(this.closeTimer);
    this.closeTimer = null;
    for (const listener of this.closeListeners) listener();
  }
}

class DevToolsClient {
  constructor(url) {
    this.url = url;
    this.socket = null;
    this.nextId = 1;
    this.pending = new Map();
    this.listeners = new Map();
  }

  async connect() {
    this.socket = new DevToolsWebSocket(this.url);
    this.socket.onMessage((raw) => this.#handleMessage(raw));
    this.socket.onError((error) => {
      this.lastTransportError = error;
      this.#rejectPending(error);
    });
    this.socket.onClose(() => {
      this.#rejectPending(
        this.lastTransportError ??
          new Error("The browser DevTools connection closed unexpectedly."),
      );
    });
    await this.socket.connect();
  }

  #handleMessage(raw) {
    let message;
    try {
      message = JSON.parse(raw);
    } catch {
      const error = new Error(
        "The browser DevTools endpoint returned a non-JSON message.",
      );
      this.lastTransportError = error;
      this.#rejectPending(error);
      this.socket.close(1002);
      return;
    }
    if (message.id) {
      const pending = this.pending.get(message.id);
      if (!pending) return;
      this.pending.delete(message.id);
      clearTimeout(pending.timeout);
      if (message.error) pending.reject(new Error(message.error.message));
      else pending.resolve(message.result);
      return;
    }
    if (!message.method) return;
    for (const listener of this.listeners.get(message.method) ?? [])
      listener(message.params ?? {});
  }

  #rejectPending(error) {
    for (const { reject, timeout } of this.pending.values()) {
      clearTimeout(timeout);
      reject(error);
    }
    this.pending.clear();
  }

  on(method, listener) {
    const listeners = this.listeners.get(method) ?? [];
    listeners.push(listener);
    this.listeners.set(method, listeners);
  }

  call(method, params = {}, timeoutMs = 15_000) {
    if (!this.socket || this.socket.readyState !== SOCKET_OPEN) {
      return Promise.reject(
        new Error(`Cannot call ${method}: DevTools is not connected.`),
      );
    }
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`Timed out waiting for ${method}.`));
      }, timeoutMs);
      this.pending.set(id, { resolve, reject, timeout });
      try {
        this.socket.sendText(JSON.stringify({ id, method, params }));
      } catch (error) {
        clearTimeout(timeout);
        this.pending.delete(id);
        reject(error);
      }
    });
  }

  close() {
    if (this.socket && this.socket.readyState < SOCKET_CLOSING)
      this.socket.close();
  }
}

function sleep(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

const client = new DevToolsClient(webSocketUrl);
await client.connect();

const browserErrors = [];
const browserLogErrors = [];
const networkFailures = [];
const requests = [];
const responses = [];
const expectedDeniedResponses = [];
client.on("Runtime.exceptionThrown", ({ exceptionDetails }) => {
  browserErrors.push(
    exceptionDetails?.exception?.description ??
      exceptionDetails?.text ??
      "Error",
  );
});
client.on("Runtime.consoleAPICalled", ({ type, args = [] }) => {
  if (!["error", "assert"].includes(type)) return;
  browserErrors.push(
    args
      .map((item) => item.value ?? item.description ?? "")
      .filter(Boolean)
      .join(" ") || type,
  );
});
client.on("Log.entryAdded", ({ entry }) => {
  if (entry?.level !== "error") return;
  browserLogErrors.push({
    source: entry.source ?? "unknown",
    text: entry.text ?? "Error",
    networkRequestId: entry.networkRequestId ?? null,
  });
});
client.on("Network.requestWillBeSent", ({ requestId, request }) => {
  requests.push({ requestId, method: request.method, url: request.url });
});
client.on("Network.responseReceived", ({ requestId, response }) => {
  responses.push({ requestId, status: response.status, url: response.url });
});
client.on(
  "Network.loadingFailed",
  ({ requestId, errorText, canceled = false, blockedReason = null }) => {
    networkFailures.push({ requestId, errorText, canceled, blockedReason });
  },
);

async function evaluate(expression) {
  const response = await client.call("Runtime.evaluate", {
    expression,
    awaitPromise: true,
    returnByValue: true,
    userGesture: true,
  });
  if (response.exceptionDetails) {
    const detail =
      response.exceptionDetails.exception?.description ??
      response.exceptionDetails.text;
    throw new Error(`Browser evaluation failed: ${detail}`);
  }
  return response.result?.value;
}

async function waitFor(
  description,
  expression,
  timeoutMs = DEFAULT_TIMEOUT_MS,
) {
  const deadline = Date.now() + timeoutMs;
  let lastError = null;
  while (Date.now() < deadline) {
    try {
      const value = await evaluate(expression);
      if (value) return value;
    } catch (error) {
      lastError = error;
    }
    await sleep(POLL_MS);
  }
  const suffix = lastError ? ` Last error: ${lastError.message}` : "";
  throw new Error(`Timed out waiting for ${description}.${suffix}`);
}

async function clickButton(text, { startsWith = false } = {}) {
  const expected = JSON.stringify(text);
  const comparison = startsWith
    ? "label.startsWith(expected)"
    : "label === expected";
  const result = await evaluate(`(() => {
    const expected = ${expected};
    const normalize = (value) => (value ?? '').replace(/\\s+/g, ' ').trim();
    const matches = [...document.querySelectorAll('button')].filter((candidate) => {
      const labels = [
        candidate.getAttribute('aria-label'),
        candidate.querySelector('.visually-hidden')?.textContent,
        candidate.textContent,
      ].map(normalize);
      return labels.some((label) => ${comparison});
    });
    const button = matches.find((candidate) => !candidate.disabled);
    if (!button) return { ok: false, reason: matches.length ? 'disabled' : 'missing' };
    button.click();
    return { ok: true, label: normalize(button.textContent) };
  })()`);
  assert.equal(
    result?.ok,
    true,
    `Could not click ${text}: ${result?.reason ?? "unknown error"}.`,
  );
}

async function waitForEnabledButton(text, { startsWith = false } = {}) {
  const expected = JSON.stringify(text);
  const comparison = startsWith
    ? "label.startsWith(expected)"
    : "label === expected";
  return waitFor(
    `enabled “${text}” button`,
    `(() => {
      const expected = ${expected};
      const normalize = (value) => (value ?? '').replace(/\\s+/g, ' ').trim();
      return [...document.querySelectorAll('button')].some((candidate) => {
        const labels = [
          candidate.getAttribute('aria-label'),
          candidate.querySelector('.visually-hidden')?.textContent,
          candidate.textContent,
        ].map(normalize);
        return labels.some((label) => ${comparison}) && !candidate.disabled;
      });
    })()`,
  );
}

async function setScanTarget(scanTarget) {
  const updated = await evaluate(`(() => {
    const input = [...document.querySelectorAll('input')].find(
      (candidate) => candidate.getAttribute('aria-label') === 'Folder or file to scan',
    );
    if (!input) return false;
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
    setter.call(input, ${JSON.stringify(scanTarget)});
    input.dispatchEvent(new Event('input', { bubbles: true }));
    input.dispatchEvent(new Event('change', { bubbles: true }));
    return true;
  })()`);
  assert.equal(updated, true, "The scan target input was not available.");
}

function observed(method, pathSuffix) {
  return requests.some((request) => {
    const url = new URL(request.url);
    return request.method === method && url.pathname.endsWith(pathSuffix);
  });
}

async function waitForRequestAfter(
  method,
  pathSuffix,
  startIndex,
  timeoutMs = DEFAULT_TIMEOUT_MS,
) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const index = requests.findIndex((request, requestIndex) => {
      if (requestIndex < startIndex) return false;
      const url = new URL(request.url);
      return request.method === method && url.pathname.endsWith(pathSuffix);
    });
    if (index >= 0) return { index, request: requests[index] };
    await sleep(POLL_MS);
  }
  throw new Error(
    `Timed out waiting for ${method} *${pathSuffix} after request index ${startIndex}.`,
  );
}

async function assertRejectedOpen(
  pathname,
  body,
  expectedStatus,
  expectedCode = null,
) {
  const requestUrl = new URL(pathname, appUrl).href;
  const launchSessionUrl = new URL("/launch-session", appUrl).href;
  const outcome = await evaluate(`fetch(${JSON.stringify(launchSessionUrl)})
    .then(async (launchResponse) => {
      if (!launchResponse.ok) throw new Error('Could not establish the local launch session.');
      const { token } = await launchResponse.json();
      return fetch(${JSON.stringify(requestUrl)}, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-RedactLens-Token': token,
        },
        body: ${JSON.stringify(JSON.stringify(body))},
      });
    })
    .then(async (response) => ({
      status: response.status,
      text: await response.text(),
    }))`);
  assert.equal(
    outcome.status,
    expectedStatus,
    `${pathname} accepted an unauthorized open request.`,
  );
  if (expectedCode !== null) {
    let problem;
    try {
      problem = JSON.parse(outcome.text);
    } catch {
      assert.fail(`${pathname} did not return a JSON problem response.`);
    }
    assert.equal(
      problem?.error?.code,
      expectedCode,
      `${pathname} returned the wrong authorization error.`,
    );
  }
  expectedDeniedResponses.push({
    status: expectedStatus,
    pathname: new URL(requestUrl).pathname,
  });
}

try {
  await Promise.all([
    client.call("Page.enable"),
    client.call("Runtime.enable"),
    client.call("Log.enable"),
    client.call("Network.enable"),
  ]);
  await client.call("Browser.setDownloadBehavior", {
    behavior: "allow",
    downloadPath,
    eventsEnabled: true,
  });
  await client.call("Page.navigate", { url: appUrl });

  await waitFor(
    "the production setup screen",
    `document.readyState === 'complete' && document.querySelector('#setup-heading')?.textContent === 'RedactLens'`,
  );
  await waitFor(
    "detector categories to load",
    `document.querySelectorAll('.cat-list input[type="checkbox"]').length >= 3`,
  );

  await setScanTarget(targetPath);
  await waitForEnabledButton("Scan this", { startsWith: true });
  await clickButton("Scan this", { startsWith: true });

  await waitFor(
    "a completed live scan and results screen",
    `document.querySelector('#results-heading')?.textContent?.includes("what I found")`,
    45_000,
  );
  await waitFor(
    "the stable five/four tier summary",
    `(() => {
      const accessibleName = (item) => (item.getAttribute('aria-labelledby') ?? '')
        .split(/\\s+/)
        .map((id) => document.getElementById(id)?.textContent?.trim() ?? '')
        .filter(Boolean)
        .join(' ');
      const labels = [...document.querySelectorAll('button.stat')].map(accessibleName);
      return labels.includes('5 Confirmed') && labels.includes('4 Double-check');
    })()`,
  );

  const eventsRequest = requests.find(({ method, url }) => {
    const pathname = new URL(url).pathname;
    return method === "GET" && /^\/scans\/[^/]+\/events$/.test(pathname);
  });
  assert.ok(eventsRequest, "The active scan session could not be identified.");
  const sessionPath = new URL(eventsRequest.url).pathname.replace(
    /\/events$/,
    "",
  );
  await assertRejectedOpen(
    `${sessionPath}/open-file`,
    { finding_id: "forged-phase9-finding" },
    404,
    "finding_not_found",
  );
  await assertRejectedOpen(
    `${sessionPath}/open-file`,
    { path: path.resolve(targetPath, "..", "outside-session.txt") },
    422,
    "invalid_request",
  );

  const revealedSource = await evaluate(`(() => {
    const button = [...document.querySelectorAll('button')].find(
      (candidate) => candidate.textContent?.trim() === 'Show in folder',
    );
    if (!button || button.disabled) return false;
    button.click();
    return true;
  })()`);
  assert.equal(
    revealedSource,
    true,
    "No source finding was available to reveal.",
  );
  await waitFor(
    "source-file reveal confirmation",
    `document.querySelector('.toast')?.textContent?.includes('Showed')`,
  );

  const filtered = await evaluate(`(() => {
    const accessibleName = (item) => (item.getAttribute('aria-labelledby') ?? '')
      .split(/\\s+/)
      .map((id) => document.getElementById(id)?.textContent?.trim() ?? '')
      .filter(Boolean)
      .join(' ');
    const button = [...document.querySelectorAll('button.stat')].find(
      (candidate) => accessibleName(candidate) === '5 Confirmed',
    );
    if (!button) return false;
    button.click();
    return true;
  })()`);
  assert.equal(filtered, true, "The Tier A summary filter was not available.");
  await waitFor(
    "the active Tier A filter",
    `[...document.querySelectorAll('button.stat')].some((button) => button.getAttribute('aria-pressed') === 'true' && button.textContent?.includes('Confirmed'))`,
  );

  await waitForEnabledButton("Tier A (5)");
  await clickButton("Tier A (5)");
  await waitForEnabledButton("Include (5)");
  await clickButton("Include (5)");
  await waitFor(
    "five persisted remediation selections",
    `(() => {
      const panel = document.querySelector('.remediation-summary');
      return panel?.querySelector('dd')?.textContent?.trim() === '5' &&
        !panel?.querySelector('button.review-btn')?.disabled;
    })()`,
  );

  await clickButton("Review remediation");
  await waitFor(
    "the remediation review dialog",
    `document.querySelector('[role="dialog"]') !== null`,
  );
  await waitForEnabledButton("Create redacted copies");
  await clickButton("Create redacted copies");
  await waitFor(
    "three verified outputs and their rescans",
    `(() => {
      const notes = [...document.querySelectorAll('.verification-note')];
      return notes.length === 3 && notes.every((note) =>
        note.textContent?.includes('Output rescan completed:'),
      );
    })()`,
    45_000,
  );

  await assertRejectedOpen(
    `${sessionPath}/open-output`,
    { finding_id: "forged-phase9-finding" },
    404,
    "finding_not_found",
  );
  await assertRejectedOpen(
    `${sessionPath}/open-output`,
    { path: path.resolve(targetPath, "..", "outside-session.txt") },
    422,
    "invalid_request",
  );

  await waitForEnabledButton("Show redacted copy in folder");
  await clickButton("Show redacted copy in folder");
  await waitFor(
    "redacted-copy reveal confirmation",
    `document.querySelector('.toast')?.textContent?.includes('Showed')`,
  );
  await clickButton("Close review");
  await waitFor(
    "the review dialog to close",
    `document.querySelector('[role="dialog"]') === null`,
  );

  const requestsBeforeExport = requests.length;
  await clickButton("Export JSON");
  const exportFreshnessRequest = await waitForRequestAfter(
    "GET",
    "/remediation",
    requestsBeforeExport,
  );
  assert.ok(
    new URL(exportFreshnessRequest.request.url).pathname.startsWith("/scans/"),
    "Export freshness must target the active scan remediation resource.",
  );
  const reportFile = path.join(downloadPath, "redactlens-report.json");
  await waitForFile(reportFile);
  const reportText = fs.readFileSync(reportFile, "utf8");
  const report = JSON.parse(reportText);

  assert.equal(report.scan.state, "complete");
  assert.equal(report.findings.length, 9);
  assert.equal(
    report.findings.filter((finding) => finding.tier === "A").length,
    5,
  );
  assert.equal(
    report.findings.filter((finding) => finding.tier === "B").length,
    4,
  );
  assert.equal(report.remediation.selected_finding_count, 5);
  assert.equal(report.outputs.length, 3);
  assert.ok(
    report.outputs.every((output) => output.verification_status === "verified"),
  );
  assert.ok(
    report.outputs.every((output) => output.rescan_status === "completed"),
  );
  assert.ok(
    report.outputs.every((output) => output.remaining_tier_a_count === 0),
  );

  const normalizedReport = reportText.replaceAll("\\", "/").toLowerCase();
  const normalizedTarget = targetPath.replaceAll("\\", "/").toLowerCase();
  assert.ok(
    !normalizedReport.includes(normalizedTarget),
    "The export leaked the absolute scan root.",
  );
  for (const internalField of [
    "matched_text",
    "start_offset",
    "end_offset",
    "evidence",
  ]) {
    assert.ok(
      !reportText.includes(`"${internalField}"`),
      `The JSON export exposed internal field ${internalField}.`,
    );
  }
  for (const secret of [
    "AKIAV3XZJH2QK7RSTUV1",
    "CorrectHorseBattery9",
    "n4Kp9xQzT2vBmR7wYsLd3aEf",
    "512-77-3049",
    "morgan.lee@northwind-co.com",
    "415-555-2671",
  ]) {
    assert.ok(
      !reportText.includes(secret),
      `The JSON export leaked raw fixture data: ${secret}`,
    );
  }

  const reportPaths = [
    ...report.scanned_files,
    ...report.findings.map((finding) => finding.file_path),
    ...report.remediation.files.flatMap((file) => [
      file.source_path,
      file.output_path,
    ]),
    ...report.outputs.flatMap((output) => [
      output.source_path,
      output.output_path,
    ]),
  ];
  assert.ok(
    reportPaths.every((item) => !path.isAbsolute(item)),
    "The report must contain relative labels instead of absolute filesystem paths.",
  );

  const notesOutput = report.outputs.find(
    (output) => path.basename(output.source_path).toLowerCase() === "notes.txt",
  );
  assert.ok(
    notesOutput,
    "The generated report did not contain the redacted notes output.",
  );
  const redactedNotes = path.resolve(targetPath, notesOutput.output_path);
  assert.ok(
    fs.existsSync(redactedNotes),
    "The generated redacted notes output was not present on disk.",
  );

  await clickButton("Scan something else");
  await waitFor(
    "the restored setup screen",
    `document.querySelector('#setup-heading')?.textContent === 'RedactLens'`,
  );
  await setScanTarget(redactedNotes);
  await waitForEnabledButton("Scan this", { startsWith: true });
  await clickButton("Scan this", { startsWith: true });
  await waitFor(
    "the redacted-output rescan results",
    `document.querySelector('#results-heading')?.textContent?.includes("what I found")`,
    45_000,
  );
  await waitFor(
    "zero Tier A and two Tier B findings in the new output scan",
    `(() => {
      const accessibleName = (item) => (item.getAttribute('aria-labelledby') ?? '')
        .split(/\\s+/)
        .map((id) => document.getElementById(id)?.textContent?.trim() ?? '')
        .filter(Boolean)
        .join(' ');
      const labels = [...document.querySelectorAll('button.stat')].map(accessibleName);
      return labels.includes('0 Confirmed') && labels.includes('2 Double-check');
    })()`,
  );
  assert.equal(
    requests.filter(
      ({ method, url }) =>
        method === "POST" && new URL(url).pathname === "/scans",
    ).length,
    2,
    "The output check must be a second browser-initiated scan.",
  );

  const requiredRequests = [
    ["GET", "/launch-session"],
    ["POST", "/scans"],
    ["POST", "/open-file"],
    ["PUT", "/remediation"],
    ["GET", "/remediation"],
    ["POST", "/remediation/generate"],
    ["POST", "/open-output"],
  ];
  for (const [method, suffix] of requiredRequests) {
    assert.ok(
      observed(method, suffix),
      `The browser did not exercise ${method} *${suffix}.`,
    );
  }
  assert.ok(
    requests.some(
      ({ method, url }) =>
        method === "GET" && new URL(url).pathname.endsWith("/events"),
    ),
    "The browser did not establish the live scan event stream.",
  );
  const failedResponses = responses.filter(({ status }) => status >= 400);
  assert.deepEqual(
    failedResponses.map(({ status, url }) => ({
      status,
      pathname: new URL(url).pathname,
    })),
    expectedDeniedResponses,
    `The live workflow received unexpected failed HTTP responses: ${failedResponses
      .map((response) => `${response.status} ${response.url}`)
      .join(", ")}`,
  );
  const unexpectedLogErrors = unexpectedBrowserLogErrors(
    browserLogErrors,
    responses,
    expectedDeniedResponses,
  );
  const unexpectedTransportFailures = unexpectedNetworkFailures(
    networkFailures,
    requests,
    responses,
  );
  const externalRequests = requests.filter(({ url }) => {
    const parsed = new URL(url);
    if (["data:", "blob:"].includes(parsed.protocol)) return false;
    return !["127.0.0.1", "localhost", "::1", "[::1]"].includes(
      parsed.hostname,
    );
  });
  assert.deepEqual(
    externalRequests,
    [],
    `The local-only UI made external requests: ${externalRequests
      .map((request) => request.url)
      .join(", ")}`,
  );
  assert.deepEqual(
    unexpectedTransportFailures,
    [],
    `Browser transport failures: ${JSON.stringify(unexpectedTransportFailures)}`,
  );
  const unexpectedErrors = [
    ...browserErrors,
    ...unexpectedLogErrors.map((entry) => entry.text),
  ];
  assert.deepEqual(
    unexpectedErrors,
    [],
    `Browser errors: ${unexpectedErrors.join(" | ")}`,
  );

  console.log(
    "Live browser E2E: React -> FastAPI -> temporary demo filesystem; 9 findings, " +
      "5 selected Tier A findings, 3 verified/rescanned outputs, source/output open routes, " +
      "forged-ID/path open rejection, privacy-safe JSON export, and a new UI scan of " +
      "notes-auto-redacted-copy.txt (0 Tier A, 2 Tier B).",
  );
} catch (error) {
  const bodyText = await evaluate(
    `document.body?.innerText?.slice(0, 2000) ?? ''`,
  ).catch(() => "");
  console.error(`Browser state: ${bodyText}`);
  const loggedErrors = [
    ...browserErrors,
    ...browserLogErrors.map((entry) => entry.text),
  ];
  console.error(`Browser errors: ${loggedErrors.join(" | ") || "none"}`);
  console.error(`Network failures: ${JSON.stringify(networkFailures)}`);
  console.error(`Requests: ${JSON.stringify(requests)}`);
  console.error(`Responses: ${JSON.stringify(responses)}`);
  throw error;
} finally {
  await client.call("Browser.close").catch(() => {});
  client.close();
}

async function waitForFile(filePath, timeoutMs = 15_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (fs.existsSync(filePath) && fs.statSync(filePath).size > 0) {
      try {
        JSON.parse(fs.readFileSync(filePath, "utf8"));
        return;
      } catch {
        // The browser may still be finishing an atomic download rename/write.
      }
    }
    await sleep(POLL_MS);
  }
  throw new Error(`Timed out waiting for browser download: ${filePath}`);
}
