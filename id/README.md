# `@worldofunreal/id`

WouID — the single identity package for World of Unreal. Auth client logic
plus the official sign-in modal. One publish, one version, every project tracks
latest. Replaces the old `@worldofunreal/id-sdk` + `@worldofunreal/id-ui`
(which are deprecated — do not use).

## Logic (any framework)

```ts
import { wouAuth } from '@worldofunreal/id';

await wouAuth.requestOtp(email);
wouAuth.setDefaultContext('cosmicrafts'); // one line per site entry
```

Electron hosts: route every call through the main-process proxy with
`setFetchImpl()` (see Hyper's `src/renderer/src/lib/wou.ts`).

## Modal (Astro sites only — needs Tailwind in the host site)

```astro
---
import AuthModal from '@worldofunreal/id/AuthModal.astro';
---

<AuthModal gameLogo="/logo.svg" gameName="World of Unreal" />
```

Props: `gameLogo` (default `/logo.svg`), `gameName`, `brandLogo`
(default `/wouid.svg` — copy `wouid.svg` into your site's `public/`),
`brandName` (default `WouID`), `title`, `subtitle`.

All element IDs are stable API — the client binds by ID, do not rename.
