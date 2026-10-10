CREATE TABLE IF NOT EXISTS privetek_job_events (
    id BIGSERIAL PRIMARY KEY,
    job_id TEXT NOT NULL REFERENCES privetek_jobs(id),
    status TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS privetek_job_events_job_id_idx ON privetek_job_events(job_id, id);
