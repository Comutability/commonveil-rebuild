// Server templates: the channels and roles a new server starts with. Names, topics and the
// rules text come from the app (src/lib/secure/serverTemplates.js), keyed by template_key, so
// a template server shows readable names before anyone has encrypted their own. Admins can
// rename anything; renamed items are encrypted like everything else.
import { DEFAULT_EVERYONE, P } from "../permissions.ts";

export type TemplateRole = { key: string; position: number; permissions: number; hoist: boolean; mentionable: boolean };
export type TemplateChannel = {
  key: string;
  kind: "category" | "text" | "announcement" | "rules" | "forum" | "voice" | "tickets";
  parent?: string;
  history?: "full" | "joined";
  slowmode?: number;
  // Overwrites by role key ("everyone" or a template role).
  overwrites?: { role: string; allow?: number; deny?: number }[];
};
export type Template = { key: string; everyone: number; roles: TemplateRole[]; channels: TemplateChannel[] };

const READ_ONLY = { role: "everyone", deny: P.SEND_MESSAGES | P.CREATE_POSTS };
const STAFF_ONLY = [
  { role: "everyone", deny: P.VIEW_CHANNEL },
  { role: "moderator", allow: P.VIEW_CHANNEL },
  { role: "support", allow: P.VIEW_CHANNEL },
];

const MODERATOR =
  P.MANAGE_MESSAGES | P.KICK_MEMBERS | P.BAN_MEMBERS | P.TIMEOUT_MEMBERS | P.VIEW_AUDIT_LOG | P.MANAGE_NICKNAMES | P.MANAGE_TICKETS |
  P.MANAGE_KEYS | P.MENTION_EVERYONE | P.MANAGE_INVITES;

/** The Commonveil community server everyone joins. */
export const COMMUNITY: Template = {
  key: "commonveil-community",
  everyone: DEFAULT_EVERYONE,
  roles: [
    { key: "admin", position: 30, permissions: P.ADMINISTRATOR, hoist: true, mentionable: true },
    { key: "moderator", position: 20, permissions: MODERATOR, hoist: true, mentionable: true },
    { key: "support", position: 10, permissions: P.MANAGE_TICKETS | P.MANAGE_MESSAGES, hoist: true, mentionable: true },
  ],
  channels: [
    { key: "start", kind: "category" },
    { key: "welcome", kind: "announcement", parent: "start", history: "full", overwrites: [READ_ONLY] },
    { key: "rules", kind: "rules", parent: "start", history: "full", overwrites: [READ_ONLY] },
    { key: "announcements", kind: "announcement", parent: "start", history: "full", overwrites: [READ_ONLY] },
    { key: "community", kind: "category" },
    { key: "general", kind: "text", parent: "community", history: "joined" },
    { key: "introductions", kind: "text", parent: "community", history: "full", slowmode: 60 },
    { key: "privacy-news", kind: "text", parent: "community", history: "full" },
    { key: "off-topic", kind: "text", parent: "community", history: "joined" },
    { key: "learn", kind: "category" },
    { key: "guides", kind: "forum", parent: "learn", history: "full" },
    { key: "show-and-tell", kind: "forum", parent: "learn", history: "full" },
    { key: "ideas", kind: "forum", parent: "learn", history: "full" },
    { key: "support", kind: "category" },
    { key: "help", kind: "forum", parent: "support", history: "full" },
    { key: "support-tickets", kind: "tickets", parent: "support", history: "full" },
    { key: "bug-reports", kind: "forum", parent: "support", history: "full" },
    { key: "voice", kind: "category" },
    { key: "lounge", kind: "voice", parent: "voice" },
    { key: "co-working", kind: "voice", parent: "voice" },
    { key: "help-desk", kind: "voice", parent: "voice" },
    { key: "staff", kind: "category" },
    { key: "staff-chat", kind: "text", parent: "staff", history: "full", overwrites: STAFF_ONLY },
    { key: "mod-notes", kind: "text", parent: "staff", history: "full", overwrites: STAFF_ONLY },
    { key: "staff-voice", kind: "voice", parent: "staff", overwrites: STAFF_ONLY },
  ],
};

/** Templates people can start their own server from. */
export const STARTER_TEMPLATES: Record<string, Template> = {
  blank: {
    key: "blank",
    everyone: DEFAULT_EVERYONE,
    roles: [],
    channels: [
      { key: "text", kind: "category" },
      { key: "general", kind: "text", parent: "text", history: "joined" },
      { key: "voice-channels", kind: "category" },
      { key: "general-voice", kind: "voice", parent: "voice-channels" },
    ],
  },
  friends: {
    key: "friends",
    everyone: DEFAULT_EVERYONE,
    roles: [],
    channels: [
      { key: "text", kind: "category" },
      { key: "general", kind: "text", parent: "text", history: "joined" },
      { key: "plans", kind: "text", parent: "text", history: "full" },
      { key: "voice-channels", kind: "category" },
      { key: "hangout", kind: "voice", parent: "voice-channels" },
    ],
  },
  study: {
    key: "study",
    everyone: DEFAULT_EVERYONE,
    roles: [],
    channels: [
      { key: "info", kind: "category" },
      { key: "welcome", kind: "announcement", parent: "info", history: "full", overwrites: [READ_ONLY] },
      { key: "study", kind: "category" },
      { key: "general", kind: "text", parent: "study", history: "joined" },
      { key: "notes", kind: "forum", parent: "study", history: "full" },
      { key: "homework-help", kind: "forum", parent: "study", history: "full" },
      { key: "voice-channels", kind: "category" },
      { key: "study-room", kind: "voice", parent: "voice-channels" },
    ],
  },
  community: {
    key: "community",
    everyone: DEFAULT_EVERYONE,
    roles: [
      { key: "moderator", position: 20, permissions: MODERATOR, hoist: true, mentionable: true },
      { key: "support", position: 10, permissions: P.MANAGE_TICKETS | P.MANAGE_MESSAGES, hoist: true, mentionable: true },
    ],
    channels: [
      { key: "start", kind: "category" },
      { key: "welcome", kind: "announcement", parent: "start", history: "full", overwrites: [READ_ONLY] },
      { key: "rules", kind: "rules", parent: "start", history: "full", overwrites: [READ_ONLY] },
      { key: "announcements", kind: "announcement", parent: "start", history: "full", overwrites: [READ_ONLY] },
      { key: "community", kind: "category" },
      { key: "general", kind: "text", parent: "community", history: "joined" },
      { key: "introductions", kind: "text", parent: "community", history: "full" },
      { key: "support", kind: "category" },
      { key: "help", kind: "forum", parent: "support", history: "full" },
      { key: "support-tickets", kind: "tickets", parent: "support", history: "full" },
      { key: "voice", kind: "category" },
      { key: "lounge", kind: "voice", parent: "voice" },
      { key: "staff", kind: "category" },
      { key: "staff-chat", kind: "text", parent: "staff", history: "full", overwrites: STAFF_ONLY },
    ],
  },
};
