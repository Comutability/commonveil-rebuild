import React from "react";
import { Link } from "react-router-dom";
import { PageHeader } from "@/components/site/bits";
import { SELF_HOSTED } from "@/api/base44Client";

// The Terms of Use. Keep the version in step with TERMS_VERSION in base44/shared/handlers/identity.ts:
// it's what people agree to at sign-up.
const UPDATED = "6 November 2026";

const SECTIONS = [
  {
    id: "about",
    title: "About these terms",
    body: [
      "These are the rules for using Commonveil at commonveil.online: the website, the app and the Commonveil Community server. By creating an account or using Commonveil, you agree to them. If you don't agree, please don't use it.",
      "Commonveil is free, open-source software, run by the Comutability community. The code itself is licensed separately, under the GNU Affero General Public License v3.0; these terms are about using our site, not about the code.",
      "Anyone can run their own Commonveil site. Those sites are run by other people, who set their own rules. These terms apply only to commonveil.online.",
    ],
  },
  {
    id: "age",
    title: "You must be 16 or older",
    body: [
      "Commonveil is for people aged 16 and over. When you create an account, you confirm that you're 16 or older.",
      "If we find out that an account belongs to someone under 16, we will close it. That means the account and everything stored with it is deleted, as described in Your data. We may find out because the person tells us, because someone reports it, or because of something they share with us.",
      "We don't ask for your date of birth, ID or a photo, and we don't store your age: only that you confirmed you're 16 or older. If you were under 16 when your account was closed, you're welcome to make a new one once you're 16.",
      "If you think someone is under 16, report them (choose \"They seem to be under 16\"). If a child is in danger, contact the police or your local emergency services first.",
    ],
  },
  {
    id: "account",
    title: "Your account",
    body: [
      "Your account is a username and a password, protected by your recovery phrase (and its other form, your private key), and optionally passkeys. Keep them safe and don't share them. Anyone who has your recovery phrase or private key can take over your account.",
      "Because of how Commonveil is built, we can't get you back into your account, or recover your messages, if you lose your password and your recovery phrase, private key, passkeys and devices. Nobody can, including us.",
      "You're responsible for what happens on your account. Tell us if you think someone else has got into it, and change your password and recovery phrase straight away.",
      "Don't choose a username or profile that pretends to be someone else, or that is hateful or sexual. Usernames can't be changed, so choose with care.",
    ],
  },
  {
    id: "encryption",
    title: "What end-to-end encryption means for you",
    body: [
      "Your messages, group names, server contents, files and calls are encrypted on your devices before they reach us. We can't read them, and we can't hand them to anyone in readable form, because we don't have the keys. What we can see is set out in Privacy.",
      "This also means we can't check what you send before it's delivered. You're responsible for what you share, and the rules below still apply to everything you do on Commonveil, encrypted or not.",
      "When someone reports something to us, we read only what they choose to show us.",
    ],
  },
  {
    id: "rules",
    title: "The rules",
    intro: "Don't use Commonveil to do any of the following, or to help anyone else do them:",
    list: [
      "Share, ask for or link to sexual images or sexual content involving anyone under 18, or try to make sexual contact with someone under 18. We report this to the authorities.",
      "Groom, exploit or put a child at risk in any way.",
      "Threaten, stalk, harass or bully anyone, or encourage others to.",
      "Attack people because of their race, ethnicity, nationality, religion, disability, sex, sexual orientation, gender identity or age.",
      "Share intimate images of someone without their consent, or threaten to.",
      "Share someone's private information (like their address) to harm or intimidate them.",
      "Promote, support or plan terrorism or violent extremism, or encourage anyone to seriously harm themselves or others.",
      "Scam, defraud or impersonate people, or trick them into giving away passwords, recovery phrases or money.",
      "Send spam or unwanted bulk messages, or run automated accounts without saying they're automated.",
      "Spread malware, or try to break into, overload, probe or disrupt Commonveil or anyone's account or device. (Found a security problem? Please report it privately instead: that's welcome.)",
      "Buy, sell or trade accounts, or make accounts to get around a block, ban or account closure.",
      "Break the law where you are, or in England and Wales.",
    ],
  },
  {
    id: "servers",
    title: "Servers and communities",
    body: [
      "Anyone can make a server. Its owner and moderators can add their own rules on top of these, and remove people who break them. They can't allow anything these terms forbid.",
      "Server owners and moderators are responsible for running their spaces fairly and for acting on reports. We can close servers that are used to break these terms.",
    ],
  },
  {
    id: "enforcement",
    title: "Reports and what we do",
    body: [
      "Report people and messages from the app. Reports to a server go to its moderators, encrypted; you can choose to tell the Commonveil team too.",
      "If someone breaks these terms, we may warn them, remove them from the Commonveil Community server, suspend their account, or close it. We'll close an account straight away for anything involving harm to children, for being under 16, for serious threats, or where the law requires it.",
      "Where the law requires, or someone is at risk of serious harm, we may share what's been reported to us with the police or other authorities. We can only share what we hold, which is set out in Privacy.",
      "If you think we got a decision wrong, tell us using the report form in the app and choose Something else. We'll look at it again.",
    ],
  },
  {
    id: "content",
    title: "What you share",
    body: [
      "What you write and share stays yours. You give us permission only to store it and pass it on to the people you share it with, which is all we can do with encrypted content anyway.",
      "Public things you write, like a server's card in Discover, can be seen by anyone, and you give us permission to show them on the site.",
    ],
  },
  {
    id: "other-sites",
    title: "Other Commonveil sites",
    body: [
      "Commonveil can talk to other Commonveil sites, so you may talk to people whose accounts are on sites run by other people. Those sites follow their own rules, and we're not responsible for how they're run. We can stop talking to any site, and you can block anyone.",
    ],
  },
  {
    id: "service",
    title: "The service",
    body: [
      "Commonveil is free. We work hard to keep it running and secure, but we provide it as it is, without promises that it will always be available, error-free or suitable for any particular use. Its encryption hasn't yet had an independent audit (see Security).",
      "We may change, add or remove features. If we ever have to close Commonveil, we'll give as much notice as we can, so you can download your data.",
      "Don't rely on Commonveil where someone's safety depends on it until an independent review has been published.",
    ],
  },
  {
    id: "ending",
    title: "Leaving, and closing accounts",
    body: [
      "You can delete your account at any time in Settings, under Data and account. What's deleted and what's kept is explained in Your data in the Help Centre.",
      "We may close an account that breaks these terms, or that the law requires us to close.",
    ],
  },
  {
    id: "liability",
    title: "Liability",
    body: [
      "Nothing in these terms limits our liability where the law doesn't allow it to be limited, such as for death or personal injury caused by negligence, or for fraud. Your legal rights as a consumer aren't affected.",
      "Otherwise, as Commonveil is a free service, we're not liable for losses caused by using it or not being able to use it, including lost messages or data, except where the law says we are.",
    ],
  },
  {
    id: "changes",
    title: "Changes to these terms",
    body: [
      "We'll update these terms when Commonveil changes or the law does. For changes that matter, we'll tell you in the app before they take effect. If you keep using Commonveil after that, the new terms apply.",
    ],
  },
  {
    id: "law",
    title: "Law",
    body: [
      "These terms are governed by the law of England and Wales. If you live elsewhere in the UK, or in another country, you may also have the protection of your local law, and can bring a claim in your local courts.",
    ],
  },
];

const LINKED = { Privacy: "/privacy", Security: "/security", "Your data": "/help/your-data" };

/** Turns "Privacy", "Security" and "Your data" in the text into links. */
function Para({ text }) {
  const parts = text.split(/(Privacy|Security|Your data)/);
  return (
    <p className="mt-3 text-muted-foreground">
      {parts.map((p, i) => (LINKED[p] ? <Link key={i} to={LINKED[p]} className="text-primary hover:underline">{p}</Link> : p))}
    </p>
  );
}

export default function Terms() {
  return (
    <>
      <PageHeader eyebrow="Terms of Use" title="The rules for using Commonveil" intro={`In plain language. Last updated ${UPDATED}.`} />
      <div className="container-cv grid gap-12 py-12 lg:grid-cols-[1fr_16rem]">
        <article className="max-w-2xl">
          {SELF_HOSTED && (
            <p className="mb-8 rounded-lg border border-border p-4 text-sm text-muted-foreground">
              This site is run by its own admins, not by commonveil.online. These are Commonveil's standard terms; this site's admins may set their own rules too.
            </p>
          )}
          {SECTIONS.map((s, i) => (
            <section key={s.id} id={s.id} className="scroll-mt-24 border-t border-border py-8 first:border-t-0 first:pt-0">
              <h2 className="text-xl font-semibold">
                <span className="mr-2 text-muted-foreground">{i + 1}.</span>
                {s.title}
              </h2>
              {s.body?.map((t) => <Para key={t} text={t} />)}
              {s.intro && <p className="mt-3 text-muted-foreground">{s.intro}</p>}
              {s.list && (
                <ul className="mt-3 list-disc space-y-2 pl-5 text-muted-foreground">
                  {s.list.map((t) => <li key={t}>{t}</li>)}
                </ul>
              )}
            </section>
          ))}
        </article>
        <aside className="hidden lg:block">
          <nav aria-label="On this page" className="sticky top-24 text-sm">
            <p className="mb-2 font-semibold">On this page</p>
            <ol className="space-y-1.5 text-muted-foreground">
              {SECTIONS.map((s, i) => (
                <li key={s.id}>
                  <a href={`#${s.id}`} className="hover:text-foreground">{i + 1}. {s.title}</a>
                </li>
              ))}
            </ol>
          </nav>
        </aside>
      </div>
    </>
  );
}
