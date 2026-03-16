CREATE TABLE IF NOT EXISTS webhook_queue (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER, -- Optional reference to the main events table for traceability
    event_type TEXT NOT NULL,
    payload TEXT NOT NULL, -- The JSON body of the webhook
    target_url TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending', -- pending, success, failed, permanent_failure
    attempt_count INTEGER NOT NULL DEFAULT 0,
    next_retry_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_error TEXT,
    FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE SET NULL
);

-- Index for the worker polling loop
CREATE INDEX IF NOT EXISTS idx_webhook_queue_pending ON webhook_queue(status, next_retry_at);
