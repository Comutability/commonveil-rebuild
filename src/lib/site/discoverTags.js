/**
 * The tags a server can put on its public card, and how they read. Shared by Discover, its cards
 * and the server settings screen that chooses them.
 */
export const TAG_LABELS = {
  privacy: "Privacy",
  security: "Security",
  "open-source": "Open source",
  learning: "Learning",
  support: "Support",
  community: "Community",
  friends: "Friends",
  study: "Study",
  gaming: "Gaming",
  creative: "Creative",
  technology: "Technology",
  local: "Local",
  activism: "Activism",
  health: "Health",
  music: "Music",
  books: "Books",
};

export const tagLabel = (t) => TAG_LABELS[t] || t;

export const ALL_TAGS = Object.keys(TAG_LABELS);