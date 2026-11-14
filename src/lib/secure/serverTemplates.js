// Readable names, topics and starting text for template servers. The backend builds a template
// server's channels and roles with only a template_key (base44/shared/servers/template.ts); the
// app shows these until an admin renames something, at which point the new name is encrypted
// like everything else. None of this is secret: it's the same for every server made from it.

const CATEGORY = (name) => ({ name });

/** Channels by template key: { name, topic }. Category names are sentence case. */
const CHANNELS = {
  // categories
  start: CATEGORY("Start here"),
  community: CATEGORY("Community"),
  learn: CATEGORY("Learn"),
  support: CATEGORY("Support"),
  voice: CATEGORY("Voice"),
  staff: CATEGORY("Staff"),
  text: CATEGORY("Text channels"),
  "voice-channels": CATEGORY("Voice channels"),
  info: CATEGORY("Information"),
  study: CATEGORY("Study"),
  // channels
  welcome: { name: "welcome", topic: "Start here: what this place is and how it works." },
  rules: { name: "rules", topic: "How we look after each other here." },
  announcements: { name: "announcements", topic: "News and updates from the team." },
  general: { name: "general", topic: "Chat about anything. New members see messages from when they join." },
  introductions: { name: "introductions", topic: "Say hello. Share as much or as little as you like." },
  "privacy-news": { name: "privacy-news", topic: "Links and discussion about privacy and security news." },
  "off-topic": { name: "off-topic", topic: "Everything else." },
  guides: { name: "guides", topic: "Step-by-step guides written by the community. One post per guide." },
  "show-and-tell": { name: "show-and-tell", topic: "Share setups, projects and things you've made." },
  ideas: { name: "ideas", topic: "Suggest features and improvements. One idea per post." },
  snips: { name: "snip-proposals", topic: "Secure Net Improvement Proposals. One thread per proposal on GitHub, opened and closed automatically." },
  help: { name: "help", topic: "Ask a question in a new post. Answers go in the thread." },
  "support-tickets": { name: "support-tickets", topic: "Private help from the support team, end-to-end encrypted." },
  "bug-reports": { name: "bug-reports", topic: "What you did, what happened, and what you expected." },
  lounge: { name: "Lounge", topic: "Hang out and talk." },
  "co-working": { name: "Co-working", topic: "Work alongside others, quietly or not." },
  "help-desk": { name: "Help desk", topic: "Talk something through with the support team." },
  "staff-chat": { name: "staff-chat", topic: "Staff only." },
  "mod-notes": { name: "mod-notes", topic: "Staff only: notes on moderation decisions." },
  "staff-voice": { name: "Staff voice", topic: "Staff only." },
  plans: { name: "plans", topic: "What's happening and when." },
  hangout: { name: "Hangout", topic: "" },
  "general-voice": { name: "General", topic: "" },
  notes: { name: "notes", topic: "Share notes. One post per topic." },
  "homework-help": { name: "homework-help", topic: "Stuck on something? Start a post." },
  "study-room": { name: "Study room", topic: "Study together." },
};

const ROLES = {
  everyone: { name: "@everyone", color: "" },
  admin: { name: "Admin", color: "#0e7490" },
  moderator: { name: "Moderator", color: "#4f46e5" },
  support: { name: "Support", color: "#b45309" },
};

const COMMUNITY_RULES = [
  "Be kind. Disagree with ideas, not people. No harassment, hate or threats.",
  "Keep it legal and safe: no malware, no scams, and never share someone else's private information.",
  "Keep each channel to its topic. Anything else goes in #off-topic.",
  "No spam, no unasked-for advertising, and no mass mentions.",
  "Never ask anyone for their recovery phrase, passcode or link code. Staff will never ask you for them.",
  "Report a problem in a support ticket or to a moderator. You can ask for a moderation decision to be looked at again in a ticket.",
];

const STARTER_RULES = [
  "Be kind and respectful.",
  "Keep each channel to its topic.",
  "No spam or unasked-for advertising.",
  "Never share someone else's private information.",
];

/** Servers by template: what a new one says before its admins write their own. */
const SERVERS = {
  "commonveil-community": {
    name: "Commonveil Community",
    description: "Help, guides, ideas and good company from the people behind Commonveil and everyone using it.",
    icon: "CV",
    color: "#0f766e",
    intro: "Everything here is end-to-end encrypted. Moderators can remove messages and members, but they can't read anything you couldn't.",
    rules: COMMUNITY_RULES,
    welcome: {
      title: "Welcome to the Commonveil Community",
      body: "This is the shared space for everyone who uses Commonveil. Ask for help, share what you've learned, suggest what we build next, or just say hello.",
      steps: [
        { channel: "rules", text: "Read the rules. You'll be asked to accept them before you post." },
        { channel: "introductions", text: "Say hello, if you'd like to." },
        { channel: "help", text: "Ask a question in the help forum, where answers stay for the next person." },
        { channel: "support-tickets", text: "Or open a private ticket with the support team." },
      ],
      privacy: [
        "Messages are encrypted on your device before they're sent, with keys only members hold.",
        "New members read #general and #off-topic from the time they join. Guides, help and announcements keep their full history.",
        "Nobody sees you in the member list unless you choose to be listed. Change it any time in this server's privacy settings.",
      ],
    },
  },
  blank: { name: "", description: "", rules: STARTER_RULES, intro: "" },
  friends: { name: "", description: "", rules: STARTER_RULES, intro: "" },
  study: {
    name: "",
    description: "",
    rules: STARTER_RULES,
    intro: "",
    welcome: {
      title: "Welcome to the study group",
      body: "Share notes, ask for help, and study together in the voice room.",
      steps: [
        { channel: "notes", text: "Share and find notes, one post per topic." },
        { channel: "homework-help", text: "Stuck? Start a post and someone will help." },
      ],
      privacy: ["Messages are encrypted on your device before they're sent, with keys only members hold."],
    },
  },
  community: {
    name: "",
    description: "",
    rules: STARTER_RULES,
    intro: "",
    welcome: {
      title: "Welcome",
      body: "Glad you're here. Have a look around, read the rules, and say hello.",
      steps: [
        { channel: "rules", text: "Read the rules." },
        { channel: "introductions", text: "Introduce yourself." },
        { channel: "help", text: "Ask questions in the help forum." },
      ],
      privacy: ["Messages are encrypted on your device before they're sent, with keys only members hold."],
    },
  },
};

/** What people can start a server from, in the order offered. */
export const STARTERS = [
  { key: "blank", title: "Start from scratch", text: "One text channel and one voice channel. Add the rest as you go." },
  { key: "friends", title: "Friends", text: "A small place to hang out and make plans." },
  { key: "study", title: "Study group", text: "Notes, homework help and a quiet room to study together." },
  { key: "community", title: "Community", text: "Rules, announcements, a help forum, support tickets and moderator roles." },
];

export const templateChannel = (key) => CHANNELS[key] || null;
export const templateRole = (key) => ROLES[key] || null;
export const templateServer = (key) => SERVERS[key] || null;

/** Colours offered for server icons and roles. */
export const COLORS = ["#0f766e", "#0e7490", "#1d4ed8", "#4f46e5", "#7c3aed", "#be185d", "#b91c1c", "#b45309", "#4d7c0f", "#475569"];

/** Up to two letters for a server's icon: initials of its first words. */
export function initialsOf(name) {
  const words = String(name || "").trim().split(/\s+/).filter(Boolean);
  if (!words.length) return "?";
  const letters = words.length === 1 ? [...words[0]].slice(0, 2) : words.slice(0, 2).map((w) => [...w][0]);
  return letters.join("").toUpperCase();
}

/** A channel name the way channels are written: lowercase words joined by hyphens. Voice channels keep their spelling. */
export function cleanChannelName(name, kind) {
  const trimmed = String(name || "").trim().slice(0, 100);
  if (kind === "voice" || kind === "stage" || kind === "category") return trimmed.replace(/\s+/g, " ");
  return trimmed.toLowerCase().replace(/[\s_]+/g, "-").replace(/[^\p{L}\p{N}-]/gu, "").replace(/-{2,}/g, "-").replace(/^-|-$/g, "");
}
