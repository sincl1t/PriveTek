-- Additive first-party counters; no contact values, URLs or report text.
CREATE TABLE IF NOT EXISTS privetek_analytics_visitors (
 id TEXT PRIMARY KEY, source TEXT NOT NULL, medium TEXT NOT NULL, campaign TEXT NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS privetek_analytics_challenges (
 challenge_id TEXT PRIMARY KEY REFERENCES privetek_account_codes(id) ON DELETE CASCADE,
 visitor_id TEXT NOT NULL REFERENCES privetek_analytics_visitors(id) ON DELETE CASCADE,
 created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS privetek_analytics_events (
 dedup_key TEXT PRIMARY KEY, kind TEXT NOT NULL,
 visitor_id TEXT REFERENCES privetek_analytics_visitors(id) ON DELETE SET NULL,
 user_id TEXT REFERENCES privetek_users(id) ON DELETE CASCADE,
 job_id TEXT, error_code INTEGER, created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS privetek_analytics_events_time ON privetek_analytics_events(created_at);
CREATE INDEX IF NOT EXISTS privetek_analytics_events_job ON privetek_analytics_events(job_id);
CREATE INDEX IF NOT EXISTS privetek_analytics_events_user ON privetek_analytics_events(user_id);
CREATE INDEX IF NOT EXISTS privetek_analytics_visitors_time ON privetek_analytics_visitors(created_at);
