# HTTP protected-context canonicalization

Foctet authenticates a versioned logical HTTP context rather than serialized
HTTP/1.1 bytes. The same rules apply when an exchange is carried by HTTP/1.1,
HTTP/2, or HTTP/3.

## Requests

- The method is converted to ASCII uppercase.
- The path and optional query are taken from `http::Uri` and bound separately.
  Percent escapes are not decoded or re-encoded. Consequently, `/a`, `/%61`,
  `/%6a`, and `/%6A` are distinct protected paths.
- The HTTP version, header ordering, whitespace, transfer encoding, and
  HTTP/2/3 pseudo-header representation are not bound.
- Authority binding is opt-in. When enabled, the URI authority is preferred and
  `Host` is used for origin-form requests. ASCII case is folded to lowercase;
  ports are not added or removed and IDNA conversion is not performed.
  Duplicate `Host` fields or disagreement between URI authority and `Host` are
  rejected.
- Each configured application header is bound by lowercase header name,
  presence, and raw value bytes. A duplicate configured header is rejected
  instead of being joined or selecting one value.

Clients and the first trusted server hop must therefore agree on the exact
request target. A reverse proxy must not decode percent escapes, normalize dot
segments, reorder query parameters, or rewrite a bound header between sealing
and opening. If a proxy rewrites authority, leave authority binding disabled or
bind against a separately authenticated, statically configured external
authority at both ends.

## Carrier headers

Every required `x-foctet-*` carrier header must occur exactly once. Optional
carrier headers may occur zero or one time. Duplicate carrier fields are
rejected before context construction; implementations must not use first-value
or comma-joining behavior.

## Responses

Responses bind direction, status, freshness, response message ID, and the
request message ID being answered. The high-level response opener requires the
initiating request message ID and rejects missing or mismatched correlation.
Streaming and one-shot response APIs use the same rule.

## Proxy deployment checklist

1. Seal after any client-side URL normalization.
2. Open before the first route, query, authority, or bound-header rewrite.
3. Preserve the raw path and query across protocol translation.
4. Reject duplicate carrier headers at every trust boundary.
5. Keep authority binding off unless both endpoints share one explicit
   normalization and proxy policy.
