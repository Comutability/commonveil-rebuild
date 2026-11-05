// Email for a self-hosted site: security notices, sign-up codes and password resets.
// Set SMTP_URL (for example smtps://user:pass@smtp.example.com:465) and MAIL_FROM to send.
// Without them nothing is sent: new accounts sign straight in, and password resets are done by an
// admin from the command line (see docs/SELF_HOSTING.md).
import nodemailer from "nodemailer";

export function createMail({ smtpUrl, from, log = console }) {
  if (!smtpUrl) {
    return {
      enabled: false,
      async send({ subject }) {
        log.info?.(`[mail] not sent (no SMTP_URL): ${subject}`);
        throw new Error("Email isn't set up on this site");
      },
    };
  }
  const transport = nodemailer.createTransport(smtpUrl);
  return {
    enabled: true,
    async send({ to, subject, body }) {
      if (typeof to !== "string" || !to.includes("@")) throw new Error("Bad address");
      await transport.sendMail({ from: from || "Commonveil <no-reply@localhost>", to, subject: String(subject).slice(0, 200), text: String(body || "") });
      return { ok: true };
    },
  };
}
