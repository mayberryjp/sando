# Frontend spec: preserve port zero in ignore-list rules

## Goal

Fix ICMP whitelisting by preserving an observed destination port of numeric `0`
when submitting `POST /api/ignorelist`. Zero is a valid recorded port value,
not a missing value and not a wildcard. ICMP has no transport-layer ports; the
value here is the port field recorded in the flow.

The backend change does not fix a frontend that still submits `dst_port: ""`.
Deploy the backend update and apply the frontend changes below.

## Request contract

Send a JSON object with `Content-Type: application/json`:

```json
{
  "ignorelist_id": "IgnoreList_10.4.60.13_10.4.20.17_1_0_NewOutboundDetection_Flow",
  "src_ip": "10.4.60.13",
  "dst_ip": "10.4.20.17",
  "dst_port": 0,
  "protocol": 1
}
```

- `ignorelist_id`, `src_ip`, `dst_ip`, `dst_port`, and `protocol` are required.
- Use the field name `protocol`, not `dst_protocol`.
- Prefer a JSON integer for `dst_port`, inclusive range **0 through 65535**.
- Decimal integer strings such as `"0"` and `"443"` are accepted for
  compatibility and normalized to integers by the backend.
- `"*"` retains its existing meaning of any port. Use it only when the user
  intentionally selects any port; never substitute it for zero or blank input.
- Missing, `null`, and empty-string ports are rejected with HTTP 400.
- Negative/out-of-range ports, booleans, fractional values, decimal-point
  strings, whitespace-only strings, arrays, and objects are rejected with HTTP 400.
- `src_port` remains optional. Preserve numeric `0` when including it.
- Keep the selected protocol unchanged, including ICMP (`1`) and ICMPv6 (`58`).
  Port zero is accepted independently of protocol, including TCP and UDP.

Successful requests retain HTTP 200 and this response:

```json
{"message": "IgnoreList entry added successfully"}
```

Validation errors return HTTP 400 with a JSON `error` string. Display that error
and retain the user's input rather than showing success or clearing the form.

## Frontend changes

Apply the same handling to alert-based whitelist actions and manual rule forms.

1. Trace the raw flow's port through display formatting, form initialization,
   validation, and request serialization. Build requests from raw values, not
   display labels such as an empty string, dash, or "N/A".
2. Do not use truthiness to decide whether a port exists. Replace patterns such
   as `port || ""`, `if (!port)`, and `filter(Boolean)` on port fields.
   `port ?? ""` preserves zero for form initialization, but blank values still
   need explicit validation before submission.
3. Before converting form text with `Number`, reject missing, `null`, blank,
   and whitespace-only input. `Number("")` and `Number(null)` produce zero and
   would silently create an unintended rule.
4. Validate numeric input with `Number.isInteger(port)` and
   `port >= 0 && port <= 65535`; set numeric inputs' minimum to `0`, not `1`.
   Handle an explicitly selected wildcard separately.
5. For ICMP, display the recorded zero clearly, optionally as
   "0 (recorded flow value; no transport port)". Do not erase or disable its
   serialization because the protocol has no transport ports.
6. Preserve zero when displaying saved rules returned by the API, including
   after a page reload.
7. Leave existing rule identifiers and rule-scope selection unchanged. This fix
   does not introduce ICMP type/code matching or new wildcard behavior.

## Matching semantics

Zero remains a literal port-value constraint. Existing backend matching checks
the rule's port against either the flow's source or destination port and accepts
either endpoint direction. This change does not narrow matching to destination
port only or change that direction handling.

An ICMP rule with port zero is not necessarily restricted to ping/echo requests.
Do not label it "ping only"; ICMP type/code filtering is outside this change.

## Acceptance tests

| Case | Expected frontend behavior |
| --- | --- |
| Supplied alert, raw port `0`, protocol `1` | POST sends numeric `dst_port: 0`; HTTP 200 |
| ICMPv6 flow, raw port `0`, protocol `58` | Zero and protocol survive submission |
| TCP/UDP flow with recorded port `0` | Zero is accepted, not treated as missing |
| Manual form containing `"0"` | Validate and submit numeric `0` |
| Optional source port `0` | Preserve `src_port: 0` if included |
| Ports `443` and `65535` | Existing successful behavior preserved |
| Missing/null/blank/whitespace input | Show validation error; do not convert to zero or wildcard |
| Negative, `65536`, fraction, boolean, or nonnumeric input | Show validation error; do not submit |
| User explicitly selects any port | Submit `"*"`, never numeric `0` |
| API returns HTTP 400 | Show `error`; retain form state; no success notification |
| Reload saved zero-port rule | Display zero rather than blank/dash |

Use the browser network inspector to verify the actual JSON request, not just
the displayed form value. Backend regression tests additionally cover SQLite
persistence, API read-back, tagging existing and future flows, and removal of
matching alerts without treating zero as a wildcard.
