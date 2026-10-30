// Security emails to a member's own sign-in address. They say what happened and when, and
// nothing else: no device names, no usernames, nothing about who they talk to. The address
// is the one their Base44 sign-in already uses; Commonveil never stores it.

/** A time as it reads in an email, e.g. "Fri, 30 Oct 2026 21:27:00 UTC". */
export const emailTime = (d: Date) => d.toUTCString().replace(" GMT", " UTC");

/** Best effort: returns whether the email service accepted the message. */
export async function emailNotice(sr: any, to: unknown, subject: string, lines: string[]): Promise<boolean> {
  try {
    const send = sr?.integrations?.Core?.SendEmail;
    if (typeof send !== "function" || typeof to !== "string" || !to.includes("@")) return false;
    await send({ to, subject: `Commonveil: ${subject}`, body: lines.join("\n") });
    return true;
  } catch {
    return false;
  }
}

const IF_NOT_YOU_DEVICE = [
  "If it wasn't you: open Commonveil on a device you trust, go to Settings, remove any device you",
  "don't recognise, and change your password.",
];

/** A device was approved from one of the member's other devices. */
export const newDeviceEmail = (when: Date) => ({
  subject: "a new device was added to your account",
  lines: [
    `A new device was linked to your Commonveil account on ${emailTime(when)}. It was approved from one of your other devices.`,
    "",
    "If that was you, there's nothing to do.",
    "",
    ...IF_NOT_YOU_DEVICE,
  ],
});

/** Someone used the recovery phrase to add a device. */
export const phraseUsedEmail = (when: Date) => ({
  subject: "your recovery phrase was used",
  lines: [
    `Your Commonveil recovery phrase was used to add a device to your account on ${emailTime(when)}.`,
    "",
    "If that was you, there's nothing to do.",
    "",
    "If it wasn't, someone else has your recovery phrase. Open Commonveil on a device you trust, go to",
    "Settings, remove any device you don't recognise, make a new recovery phrase there, and change your password.",
  ],
});

/** Someone asked for a reset; it completes after the waiting period unless it's stopped. */
export const resetRequestedEmail = (effectiveAt: Date) => ({
  subject: "someone asked to reset your encryption keys",
  lines: [
    "Someone signed in to your Commonveil account and asked to reset its encryption keys.",
    "",
    `If that was you, there's nothing to do. The reset completes on ${emailTime(effectiveAt)}.`,
    "",
    "If it wasn't you: open Commonveil on one of your devices, where you'll see the request and can cancel it,",
    "or unlock your keys with your recovery phrase, which cancels it too. Then change your password.",
    "",
    "Until the reset completes, nothing changes: your devices, keys and messages stay as they are.",
  ],
});

/** A reset finished: the account has new keys and its other devices were removed. */
export const resetDoneEmail = (when: Date) => ({
  subject: "your encryption keys were reset",
  lines: [
    `The encryption keys on your Commonveil account were reset on ${emailTime(when)}, a week after the reset was asked for.`,
    "Your other devices were removed, and the people you talk to will see that your keys changed.",
    "",
    "If that was you, there's nothing to do.",
    "",
    "If it wasn't, someone with your password has taken over your keys. Change your password straight away,",
    "then use Report a security problem on the Commonveil Security page so we can help.",
  ],
});

/** An account set to delete itself after a stretch without use is about to be deleted. */
export const inactiveWarningEmail = (deleteOn: Date, days: number) => ({
  subject: "your account will be deleted soon",
  lines: [
    `You asked for your Commonveil account to be deleted after ${days} days without use, and it hasn't been used for a while.`,
    "",
    `It will be deleted on or after ${emailTime(deleteOn)}, with everything in it. That can't be undone.`,
    "",
    "To keep it, just sign in to Commonveil before then. You can turn this off in Settings.",
  ],
});
