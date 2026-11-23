# Subscription tracker pilot

The account tab `/account#section-subscriptions` detects **possible** recurring payments from a user-selected CSV. It does not establish whether a subscription is currently active, used, cancelled, or billed through another account. No external financial provider, bank credentials, email scanning, payments, or scheduled notifications are connected.

## Import

The file stays in browser memory (up to 2 MiB / 10,000 data rows / 50 columns). The user chooses UTF-8 or Windows-1251 and the sign used for outgoing amounts. Positive-only mode requires an expense-only export. Accepted separators: comma, semicolon, tab; quoted fields supported. Headers: `date;merchant;amount;currency`, or the Russian equivalents listed in `subscription-core.js`. Dates: ISO or DD.MM.YYYY / DD/MM/YYYY. Amounts: signed decimal with at most two decimal places. Currency may be chosen explicitly when the column is absent. Unsupported rows are counted and skipped visibly.

Groups require the same normalized description and currency, two or more observations, amount variation within 20% of the median, and consistent weekly/monthly/quarterly/yearly intervals. Exact duplicate rows are ignored and counted. Varying descriptions, mixed intervals, irregular or usage-based charges, trials, refunds and sparse statements can prevent detection or yield false candidates. No completeness claim is made. At most 100 candidates are displayed and up to 100 entries saved.

## Account storage

Only selected metadata is sent on explicit Save: merchant, amount, currency, period, last payment date, user status and random ID. Raw file, individual transactions, card/account numbers, CSV provenance and candidate evidence are never submitted. The list is encrypted with the existing account report key and bound to the authenticated user ID; unknown fields are rejected. New migration `013_subscription_lists.sql` adds a separate table with cascading user deletion. Empty list overwrites the current list with an encrypted empty payload. Account deletion removes its row. Revisions prevent concurrent tabs overwriting each other silently.

GET/PUT `/api/account/subscriptions`: existing session authentication; PUT requires same-origin and CSRF token, bounded 64 KiB JSON, generic storage errors, no-store response headers. No new secrets or paid resources. Deployment applies the additive migration through existing startup migration handling; backups retain historical database contents according to existing retention.

## Display

Review / user-confirmed active / cancelled / not subscription. Only active items contribute to approximate monthly totals. Currencies remain separate. Expected next payment is an estimate based on the last observed payment (end-of-month clamping); overdue prompts appear only when opening the tab. Manual entry and removal available. Re-import does not replace saved subscriptions without explicit user action. There is no automated cancellation or verification of a vendor cancellation.

## Validation

`node tests/js/subscriptions.test.cjs` tests parsing, negative vs positive direction, currencies, calendar dates, duplicate rows, variable amounts, irregular input and forecasts. `pytest tests/test_subscriptions.py` tests authentication, CSRF, owner binding, validation, encrypted persistence and revision conflicts against a disposable local PostgreSQL when configured. Browser preview uses synthetic data and a simulated account store; it is not a production-account verification.
