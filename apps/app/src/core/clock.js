// The per-replica logical clock that stamps every op's `created_at`. A Hybrid Logical Clock (HLC):
// physical wall-clock milliseconds, made STRICTLY monotonic with a `+1` logical tiebreak when physical
// time hasn't advanced. This is a correctness requirement of the claim engine, not a nicety: a claim's
// content-hash id covers `created_at`, so two ops minted in the same wall-clock millisecond would
// collide to one id — and a re-assert reproducing a still-tombstoned id folds straight back to dead
// (openom-crdt's materialize kills by id). `created_at` is provenance-only (never a convergence
// tiebreak), so advancing it a fraction ahead of wall-clock within a burst is inert to ordering.
//
// One instance per open tree/replica. (The robust end state is for the wasm engine to own this and
// stamp `created_at` itself, so no caller can violate the invariant — a follow-up; today the JS write
// adapter is the single stamping site and holds the clock.)
export class Clock {
  #last = 0;

  /** The next strictly-increasing timestamp (epoch ms, logical-bumped on a tie). */
  now() {
    const t = Date.now();
    this.#last = t > this.#last ? t : this.#last + 1;
    return this.#last;
  }
}
