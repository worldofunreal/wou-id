# `@worldofunreal/id-ui`

Official WouID sign-in modal (Astro). Single source — do not vendor copies.

```astro
---
import AuthModal from '@worldofunreal/id-ui/AuthModal.astro';
---

<AuthModal gameLogo="/logo.svg" gameName="World of Unreal" />
```

Props: `gameLogo` (default `/logo.svg`), `gameName`, `brandLogo`
(default `/wouid.svg` — copy `wouid.svg` into your site's `public/`),
`brandName` (default `WouID`), `title`, `subtitle`.

Requires `@worldofunreal/id-sdk` (peer install) and Tailwind in the host site.
All element IDs are stable API — the SDK client binds by ID, do not rename.
