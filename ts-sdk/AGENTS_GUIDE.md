# 📖 WOU-ID Client SDK — Guía Oficial para Agentes de IA

Esta guía es de lectura obligatoria para cualquier agente antes de integrar autenticación en `worldofunreal.com`, `cosmicrafts.com`, `nftropoly.com`, `shadowsofwar.io` o cualquier nuevo frontend.

---

## 1. Arquitectura Centralizada de Identidad (SSO Hub)

Para evitar errores de `redirect_uri_mismatch` en Google Cloud Console, Discord Developer y Apple Developer:

```
[ frontend: cosmicrafts.com / nftropoly.com / localhost ]
                       │
                       │  wouAuth.loginWithOAuth('google')
                       ▼
        [ https://id.worldofunreal.com ]
                       │
                       │  redirect_uri = https://worldofunreal.com/auth/callback
                       ▼
            [ Google / Discord / X ] (Acepta la URI autorizada)
                       │
                       │  Redirect con Auth Code
                       ▼
   [ https://worldofunreal.com/auth/callback ] (Hub Central)
                       │
                       │  Intercambia código, emite session_token y PlayerAccount
                       ▼
   [ Redirige a: https://cosmicrafts.com/profile?session_token=...&account=... ]
                       │
                       ▼
   [ wouAuth auto-hidrata la sesión y emite 'wou:auth-state-change' ]
```

> [!IMPORTANT]
> **REGLA INVIOLABLE:** NUNCA envíes `window.location.origin/auth/callback` a Google u OAuth providers externos desde páginas satélite. El SDK ya utiliza automáticamente el Hub Central en `https://worldofunreal.com/auth/callback`.

---

## 2. API Canónica del SDK (`wouAuth`)

### A. Métodos de Sesión
```typescript
import { wouAuth, type PlayerAccount } from './wou-auth';

// Estado actual
const user: PlayerAccount | null = wouAuth.getUser();
const isAuth: boolean = wouAuth.isAuthenticated();

// Escuchar cambios reactivos en cualquier componente
window.addEventListener('wou:auth-state-change', (e: any) => {
  const { authenticated, user, token } = e.detail;
  console.log('Nuevo estado:', authenticated, user);
});
```

### B. Métodos de Login
```typescript
// Social OAuth (Google, Discord, Twitter, Meta)
wouAuth.loginWithOAuth('google'); // o alias wouAuth.loginWithSocial('google')

// Email OTP
await wouAuth.sendEmailOtp('jugador@gmail.com');
await wouAuth.verifyEmailOtp('jugador@gmail.com', '123456');

// Web3
await wouAuth.loginWithEthereum(); // o alias wouAuth.loginWithEvm()
await wouAuth.loginWithSolana();
await wouAuth.loginWithInternetIdentity(); // o alias wouAuth.loginWithIcp()

// Cierre de Sesión
wouAuth.logout();
```

### C. Métodos Sociales & Clanes
```typescript
// Búsqueda en vivo de jugadores (Debounce recomendado 250ms)
const results = await wouAuth.searchPlayers('bizkit', 10);

// Clanes
const clans = await wouAuth.getClans(20);
const details = await wouAuth.getClanDetails('SOW');
await wouAuth.createClan('TAG', 'Clan Name', 'Description', '⚔️');
await wouAuth.joinClan('TAG');
await wouAuth.leaveClan('TAG');
```

---

## 3. Despliegue de Frontends a Producción (GitHub Actions)

Todo repositorio frontend de Astro (`worldofunreal.com`, `cosmicrafts.com`, `nftropoly`) se despliega **exclusivamente** mediante push a `master`:

```yaml
# .github/workflows/deploy.yml
name: Deploy to Production
on:
  push:
    branches: [master, main]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '22'
          cache: 'npm'
      - run: npm ci || npm install
      - run: npm run build
      - uses: webfactory/ssh-agent@v0.10.0
        with:
          ssh-private-key: ${{ secrets.SSH_PRIVATE_KEY }}
      - name: Deploy to IONOS
        run: |
          mkdir -p ~/.ssh
          ssh-keyscan -H ${{ secrets.SSH_HOST }} >> ~/.ssh/known_hosts
          rsync -avz --delete dist/ ${{ secrets.SSH_USER }}@${{ secrets.SSH_HOST }}:/var/www/<DOMINIO>/dist/
```

> [!WARNING]
> Prohibido inventar despliegues manuales con `scp` o modificar servicios sin backup. Si un deploy falla, el pipeline es ley.
