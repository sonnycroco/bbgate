---
title: Customer PII readable across accounts via GET /api/v2/customers/{id}
vuln_class: idor
target_host: api.example.com
program: example-bbp
severity: high
found_at: 2026-08-24
ai_drafted_at: 2026-08-24T18:05:00
impact_tier: demonstrated
impact:
  attacker_position: "free-tier authenticated user, own customer_id 41982"
  action: "change the customer_id path segment in GET /api/v2/customers/{id} to an id belonging to another account"
  asset: "full name, email address, phone number and postal address of any other customer"
  precondition: ""
repro:
  - "Register a free account at https://app.example.com/signup and complete email verification."
  - "Log in, open the network tab, and copy the Bearer token off any request to api.example.com."
  - "Send GET https://api.example.com/api/v2/customers/41982 with that token. The response is your own record."
  - "Send the same request with the id 41983. The response is a different customer's record: name, email, phone, postal address."
  - "Register a second account, note its customer_id, and read it from the first account's token to confirm the read is not scoped to the caller."
clean_state_runs:
  - ran_at: 2026-08-24T17:40:00
    from_state: fresh
    result: reproduced
    deviations: []
suspected_duplicate: false
---

# Customer PII readable across accounts via GET /api/v2/customers/{id}

## Summary

`GET /api/v2/customers/{id}` authenticates the caller but never checks that the
requested `customer_id` belongs to them. Any authenticated account, including a
free-tier one created in under a minute, can read the full customer record of
any other account by changing one number in the path.

## Details

The endpoint sits behind the standard Bearer token check, so an unauthenticated
request gets a 401. With a valid token, the response for the caller's own id and
the response for someone else's id are indistinguishable in shape: same 200,
same fields, same latency. There is no ownership check anywhere in the path.

Customer ids are sequential. Account 41982 was issued on signup, and 41983 was
issued to the next person to register. Walking the range is trivial and nothing
rate limits it below a few hundred requests a minute.

The record returned holds `full_name`, `email`, `phone`, `address_line_1`,
`address_line_2`, `postcode` and `created_at`. It does not hold payment data.

## Impact

A free account is enough to read the name, email, phone number and home address
of every customer in the system. At sequential ids and no meaningful rate limit,
that is the whole customer table, not a targeted read.

## Remediation

Check ownership at the handler, not at the router: reject the request unless the
authenticated principal owns the requested `customer_id` or holds an explicit
support role. Non-sequential ids would raise the cost of enumeration but they do
not fix the missing authorisation check.
