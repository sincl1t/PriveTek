CREATE TABLE privetek_breach_catalogue (
    name_key TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    breach_date TEXT NOT NULL,
    refreshed_at TIMESTAMPTZ NOT NULL
);
