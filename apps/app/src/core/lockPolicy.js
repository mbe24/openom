// LockPolicy — decides WHEN to auto-lock and calls back to free the key. It is deliberately
// platform-agnostic: it knows nothing about the sealer/worker, only an `onLock(reason)`
// callback (the app's lockNow). That's the seam a Tauri build extends — native background /
// app-lifecycle triggers call the same onLock; nothing here changes.
//
// Web trigger sources:
//   - An IDLE timer keyed on an ABSOLUTE deadline. A hidden tab (and a suspended mobile
//     webview) throttles or freezes setTimeout, so a naive timer could leave the app unlocked
//     long past its deadline. Storing the deadline and re-checking it when the page becomes
//     visible again closes that hole ("laptop shut for an hour" locks on return).
//   - visibilitychange, to run that re-check.
//
// The policy only counts while ARMED — i.e. a real, lockable session is open. At the gate, or
// during the demo (no keyring to re-unlock), it stays disarmed so it can't strand the user.

export function createLockPolicy({ onLock, now = () => Date.now(), target = window, doc = document }) {
  let idleMs = 0;     // 0 = idle-lock off
  let armed = false;  // true only while a lockable session is open
  let deadline = 0;   // absolute timestamp the idle lock is due
  let timer = null;

  const clearTimer = () => { if (timer) { clearTimeout(timer); timer = null; } };

  function reschedule() {
    clearTimer();
    if (!armed || !idleMs) return;
    timer = setTimeout(tick, Math.max(0, deadline - now()));
  }
  function tick() {
    timer = null;
    if (!armed || !idleMs) return;
    if (now() >= deadline) onLock('idle');
    else reschedule(); // activity moved the deadline out — wait the remainder
  }
  function bump() {
    if (!armed || !idleMs) return;
    deadline = now() + idleMs;
    reschedule();
  }
  function onVisibility() {
    if (doc.visibilityState !== 'visible') return;
    // Timers may have been frozen while hidden — the deadline can already be past.
    if (armed && idleMs && now() >= deadline) onLock('idle');
    else reschedule();
  }

  const activity = ['pointerdown', 'keydown', 'wheel', 'touchstart'];
  for (const ev of activity) target.addEventListener(ev, bump, { passive: true });
  doc.addEventListener('visibilitychange', onVisibility);

  return {
    /** Set the idle window in minutes (0 disables idle-lock). */
    setIdleMinutes(min) {
      idleMs = Math.max(0, Number(min) || 0) * 60000;
      if (!idleMs) clearTimer();
      else bump();
    },
    /** Begin counting — call when a lockable session opens. */
    arm() { armed = true; bump(); },
    /** Stop counting — call on lock and whenever the gate is up. */
    disarm() { armed = false; clearTimer(); },
  };
}
