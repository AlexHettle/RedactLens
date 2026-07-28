function matchesExpectedDeniedResponse(response, expectedDeniedResponses) {
  if (!response.requestId) return false;
  const pathname = new URL(response.url).pathname;
  return expectedDeniedResponses.some(
    (expected) =>
      response.status === expected.status && pathname === expected.pathname,
  );
}

/**
 * Keep every browser log error except the network entry emitted automatically
 * for an HTTP denial that the live workflow has already proved intentional.
 */
export function unexpectedBrowserLogErrors(
  entries,
  responses,
  expectedDeniedResponses,
) {
  const expectedRequestIds = new Set(
    responses
      .filter((response) =>
        matchesExpectedDeniedResponse(response, expectedDeniedResponses),
      )
      .map((response) => response.requestId),
  );

  return entries.filter(
    (entry) =>
      entry.source !== "network" ||
      !entry.networkRequestId ||
      !expectedRequestIds.has(entry.networkRequestId),
  );
}

function isExpectedCompletedRequestCancellation(failure, requests, responses) {
  if (
    !failure.canceled ||
    failure.errorText !== "net::ERR_ABORTED" ||
    failure.blockedReason
  ) {
    return false;
  }

  const request = requests.find(
    (candidate) => candidate.requestId === failure.requestId,
  );
  const response = responses.find(
    (candidate) => candidate.requestId === failure.requestId,
  );
  if (!request || !response) return false;

  const pathname = new URL(request.url).pathname;
  const completedScanDeletion =
    request.method === "DELETE" &&
    response.status === 204 &&
    /^\/scans\/[^/]+$/.test(pathname);
  const closedEventStream =
    request.method === "GET" &&
    response.status === 200 &&
    /^\/scans\/[^/]+\/events$/.test(pathname);
  const savedAppearanceTheme =
    request.method === "PUT" &&
    response.status === 204 &&
    pathname === "/appearance/theme";
  return completedScanDeletion || closedEventStream || savedAppearanceTheme;
}

/** Keep transport failures except completed requests Chrome cancels during UI transitions. */
export function unexpectedNetworkFailures(failures, requests, responses) {
  return failures.filter(
    (failure) =>
      !isExpectedCompletedRequestCancellation(failure, requests, responses),
  );
}
