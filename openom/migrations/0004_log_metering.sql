-- Delta-log metering (track B1). Two independent gates on the append path:
--
--   1. Abuse rate — a per-account token bucket. `log_rate` is the sustained
--      appends/sec; `log_burst` the bucket capacity (headroom for a reconnecting
--      client flushing a backlog). Enforced in one atomic UPDATE on append, so it's
--      correct across the stateless Lambda fleet — there is no per-instance state to
--      race (a per-process limiter would let N cold Lambdas grant N× the rate).
--
--   2. Byte capacity — reuses the existing tree_used_bytes / max_tree_bytes meter
--      (§17). This is an INDEPENDENT axis from the media pool: a full log can't lock
--      a user out of media and a full media pool can't block edits (§17 two-meter).
--
-- Defaults are a generous baseline for a real editing client and restrictive against
-- a hammering abuser; billing (or the local seed) overrides per account. Existing
-- rows adopt the defaults, starting with a full bucket.
ALTER TABLE accounts
    ADD COLUMN log_rate        DOUBLE PRECISION NOT NULL DEFAULT 10,    -- sustained appends/sec
    ADD COLUMN log_burst       INTEGER          NOT NULL DEFAULT 200,   -- bucket capacity (tokens)
    ADD COLUMN log_tokens      DOUBLE PRECISION NOT NULL DEFAULT 200,   -- current tokens; starts full
    ADD COLUMN log_refilled_at TIMESTAMPTZ      NOT NULL DEFAULT now(); -- last refill instant
