-- OPE-415: a per-tree cursor so the scheduled log-GC can BATCH — each run marks the N least-recently-swept
-- trees and stamps last_gc_at, so successive runs rotate through every tree without one run blowing the
-- Lambda budget. NULL (never swept) sorts first, so new trees are picked up promptly.
ALTER TABLE trees ADD COLUMN IF NOT EXISTS last_gc_at TIMESTAMPTZ;

-- The batch order: least-recently-swept first (NULLs first). Partial-free; small table, but keeps the
-- ORDER BY + LIMIT cheap as tree count grows.
CREATE INDEX IF NOT EXISTS trees_last_gc_at_idx ON trees (last_gc_at NULLS FIRST);
