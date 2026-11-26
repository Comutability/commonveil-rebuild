// One run at a time: a call made while a run is on its way asks for one more run after it, whether
// that run succeeds or fails, so the newest state is always the one that goes last. Used for the
// browser's push choice (push.js, sayAlerts); separate so it can be tested without a browser.

/** Wrap `run` (async, no arguments) so calls never overlap; an error is rethrown only if the last run failed. */
export function serialise(run) {
  let busy = false;
  let again = false;
  return async function serial() {
    if (busy) {
      again = true;
      return;
    }
    busy = true;
    let failed = null;
    try {
      do {
        again = false;
        failed = null;
        await run().catch((err) => {
          failed = err;
        });
      } while (again);
    } finally {
      busy = false;
    }
    if (failed) throw failed;
  };
}
