// The emoji people can react with: a fixed list, so a reaction can only ever say which of these
// it is and can't carry a hidden message. The first six are the quick reactions.
// Each entry is "emoji|name". Names are what screen readers announce and what search matches.

const GROUPS = {
  Smileys: [
    "😀|Grinning", "😃|Big smile", "😄|Smiling eyes", "😁|Beaming", "😆|Laughing hard", "😅|Nervous laugh", "🤣|Rolling on the floor",
    "😂|Laughing", "🙂|Slight smile", "🙃|Upside down", "😉|Wink", "😊|Blush", "😇|Halo", "🥰|Hearts", "😍|Heart eyes", "🤩|Star struck",
    "😘|Blowing a kiss", "😋|Yum", "😛|Tongue out", "😜|Winking tongue", "🤪|Zany", "🤑|Money mouth", "🤗|Hug", "🤭|Hand over mouth",
    "🤫|Shush", "🤔|Thinking", "🤐|Zipped mouth", "🤨|Raised eyebrow", "😐|Neutral", "😑|Expressionless", "😶|No mouth", "😏|Smirk",
    "😒|Unamused", "🙄|Eye roll", "😬|Grimace", "😌|Relieved", "😔|Pensive", "😪|Sleepy", "😴|Sleeping", "😷|Mask", "🤒|Thermometer",
    "🤢|Nauseous", "🥵|Hot", "🥶|Cold", "🥴|Woozy", "😵|Dizzy", "🤯|Mind blown", "🤠|Cowboy", "🥳|Party", "😎|Cool", "🤓|Nerd",
    "😕|Confused", "😟|Worried", "😮|Surprised", "😲|Astonished", "🥺|Pleading", "😢|Sad", "😭|Crying", "😱|Screaming", "😖|Confounded",
    "😞|Disappointed", "😓|Sweat", "😩|Weary", "😤|Triumph", "😡|Angry", "🤬|Swearing", "💀|Skull", "💩|Poo", "🤡|Clown", "👻|Ghost",
    "👽|Alien", "🤖|Robot",
  ],
  People: [
    "👍|Thumbs up", "👎|Thumbs down", "👏|Clapping", "🙌|Raised hands", "👐|Open hands", "🤝|Handshake", "🙏|Thank you", "✌️|Victory",
    "🤞|Fingers crossed", "🤟|Love you", "🤘|Rock on", "👌|OK", "🤌|Pinched fingers", "👈|Pointing left", "👉|Pointing right",
    "👆|Pointing up", "👇|Pointing down", "☝️|Index up", "✋|Raised hand", "👋|Wave", "🤙|Call me", "💪|Strong", "🫡|Salute",
    "🫶|Heart hands", "👀|Eyes", "🧠|Brain", "🫠|Melting",
  ],
  Hearts: [
    "❤️|Heart", "🧡|Orange heart", "💛|Yellow heart", "💚|Green heart", "💙|Blue heart", "💜|Purple heart", "🖤|Black heart",
    "🤍|White heart", "🤎|Brown heart", "💔|Broken heart", "💕|Two hearts", "💖|Sparkling heart", "💯|Hundred", "💥|Boom", "💫|Dizzy star",
    "💬|Speech bubble", "💤|Zzz",
  ],
  Nature: [
    "🐶|Dog", "🐱|Cat", "🐭|Mouse", "🐰|Rabbit", "🦊|Fox", "🐻|Bear", "🐼|Panda", "🐨|Koala", "🐯|Tiger", "🦁|Lion", "🐸|Frog",
    "🐵|Monkey", "🐧|Penguin", "🐦|Bird", "🦉|Owl", "🐝|Bee", "🦋|Butterfly", "🐢|Turtle", "🐙|Octopus", "🐳|Whale", "🌸|Blossom",
    "🌻|Sunflower", "🌲|Tree", "🌵|Cactus", "🍀|Clover", "🍁|Maple leaf", "🌈|Rainbow", "☀️|Sun", "🌙|Moon", "⭐|Star", "✨|Sparkles",
    "⚡|Lightning", "🔥|Fire", "❄️|Snowflake", "🌊|Wave of water",
  ],
  Food: [
    "🍎|Apple", "🍌|Banana", "🍓|Strawberry", "🍉|Watermelon", "🍋|Lemon", "🥑|Avocado", "🌶️|Chilli", "🥕|Carrot", "🍞|Bread", "🧀|Cheese",
    "🍕|Pizza", "🍔|Burger", "🍟|Chips", "🌮|Taco", "🍜|Noodles", "🍣|Sushi", "🍪|Biscuit", "🎂|Birthday cake", "🍫|Chocolate",
    "🍿|Popcorn", "☕|Hot drink", "🍵|Tea", "🍺|Beer", "🍷|Wine", "🥂|Cheers",
  ],
  Activities: [
    "🎉|Celebration", "🎊|Confetti", "🎈|Balloon", "🎁|Gift", "🏆|Trophy", "🥇|Gold medal", "⚽|Football", "🏀|Basketball", "🎾|Tennis",
    "🎮|Video game", "🎲|Dice", "🧩|Puzzle", "🎨|Art", "🎵|Music", "🎸|Guitar", "🎤|Microphone", "🎧|Headphones", "🎬|Film", "📚|Books",
  ],
  Travel: [
    "🚀|Rocket", "✈️|Plane", "🚗|Car", "🚲|Bicycle", "🚂|Train", "⛵|Sailing boat", "🏠|House", "🏕️|Camping", "🌍|Earth", "🗺️|Map",
    "⏰|Alarm clock", "⌛|Hourglass",
  ],
  Objects: [
    "💡|Idea", "🔒|Locked", "🔑|Key", "🛡️|Shield", "🔧|Spanner", "🔨|Hammer", "⚙️|Gear", "🧪|Test tube", "💻|Laptop", "📱|Phone",
    "📷|Camera", "📌|Pin", "📎|Paper clip", "📝|Memo", "📅|Calendar", "📈|Chart going up", "📉|Chart going down", "💰|Money bag",
    "🔔|Bell", "📣|Megaphone", "🧭|Compass", "🪄|Magic wand",
  ],
  Symbols: [
    "✅|Done", "☑️|Ticked box", "✔️|Tick", "❌|Cross", "❎|Cross mark", "⭕|Circle", "❗|Exclamation", "❓|Question", "‼️|Double exclamation",
    "⚠️|Warning", "🚫|No entry", "⛔|Stop", "♻️|Recycle", "➕|Plus", "➖|Minus", "🆗|OK button", "🆕|New", "🆒|Cool button", "🔴|Red circle",
    "🟢|Green circle", "🔵|Blue circle", "🟡|Yellow circle", "⬆️|Up", "⬇️|Down", "➡️|Right", "⬅️|Left", "🔁|Repeat", "➡|Right arrow",
  ],
};

/** Quick reactions, shown first and in the hover bar. */
export const QUICK_REACTIONS = Object.freeze(["👍", "❤️", "😂", "😮", "😢", "🙏"]);

export const EMOJI = Object.freeze(
  Object.entries(GROUPS).flatMap(([group, items]) =>
    items.map((s) => {
      const [e, name] = s.split("|");
      return Object.freeze({ e, name, group });
    }),
  ).filter((x, i, all) => all.findIndex((y) => y.e === x.e) === i),
);

export const EMOJI_GROUPS = Object.freeze(Object.keys(GROUPS));

const BY_CHAR = new Map(EMOJI.map((x) => [x.e, x]));

/** True for an emoji people can react with. */
export const isReactionEmoji = (e) => typeof e === "string" && BY_CHAR.has(e);

export const emojiName = (e) => BY_CHAR.get(e)?.name || "Reaction";

/** Emoji whose name matches a search, in list order. */
export function searchEmoji(query) {
  const q = String(query || "").trim().toLowerCase();
  if (!q) return EMOJI;
  return EMOJI.filter((x) => x.name.toLowerCase().includes(q));
}

/** Sort key: quick reactions first, then the list's own order. */
export function emojiOrder(e) {
  const quick = QUICK_REACTIONS.indexOf(e);
  if (quick >= 0) return quick;
  const i = EMOJI.findIndex((x) => x.e === e);
  return i < 0 ? 10_000 : 100 + i;
}
