# Installing Commonveil

Commonveil is a web app that can be installed. It gets its own icon, opens in its own window, starts
straight in your messages and keeps working without a connection. It isn't an app-store app or a native
download: it's this website, from this site, so there's nothing extra to trust and updates arrive by
themselves.

## How to install

- **Chrome, Edge and other Chromium browsers (Windows, macOS, Linux, ChromeOS, Android):**
  **Settings → Install the app → Install Commonveil**, or the install icon in the address bar, or the
  browser menu's **Install** / **Add to Home screen**.
- **iPhone and iPad:** in Safari, tap **Share**, then **Add to Home Screen**. Open it from the Home
  Screen to get push notifications ([NOTIFICATIONS.md](NOTIFICATIONS.md)).
- **Safari on macOS:** **File → Add to Dock**.
- **Firefox:** on Android, **Add to Home screen**. Firefox on desktop doesn't install web apps; use it
  in a tab, which works the same.

## What the installed app does differently

- Its own window, without the address bar, using the full screen on phones (it respects notches and
  rounded corners).
- Opens straight to `/app`. Shortcuts on the icon go to messages, Discover and settings.
- Shows an app badge for new notifications, where the system supports it.
- **Update now:** when a new version is ready, a bar offers to switch to it. Nothing changes under you
  mid-conversation.

## What it keeps on your device

The service worker (`public/sw.js`) keeps only the app's own code (pages, scripts, styles, icons) so it
opens fast and offline. It never keeps anything from the backend: no messages, keys, profiles or files.
Requests to `/api/`, `/cvp/`, `/.well-known/`, `/u/` and the worker itself always go to the network.
Your encrypted data stays where it always was, in the app's encrypted local storage
([OFFLINE.md](OFFLINE.md)).

Pages are fetched from the network first so you get updates; the kept copy is used only when you're
offline. Built files are named after their contents, so a kept copy can't be stale.

## Security

- The app runs under the same Content Security Policy as the site. The service worker is registered
  through the `service-worker` Trusted Types policy, and `sw.js` and the manifest are served with
  `no-cache`, so a new version is always checked for.
- Installing grants no extra permissions. Notifications, the microphone and the camera still ask.
- Uninstalling removes the window and icon. To clear what the browser kept, clear the site's data in
  the browser's settings.

## For self-hosted sites

Nothing to configure. The manifest, icons and worker ship with the build. Installing needs HTTPS (or
`localhost` while testing).
