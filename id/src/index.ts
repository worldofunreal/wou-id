/**
 * World of Unreal Universal Identity & Cross-Game SDK
 * (C) 2026 World of Unreal. MIT License.
 */

export const ID_SERVER_URL = 'https://id.worldofunreal.com';
export const AUTH_HUB_CALLBACK_URL = 'https://worldofunreal.com/auth/callback';
// Official product brand. Wordmark is `WouID`; logo ships at `assets/wouid.svg`.
export const WOUID_BRAND_NAME = 'WouID';
export const WOUID_LOGO_URL = 'https://worldofunreal.com/wouid.svg';
// Single canonical legal home for the org (Hyper points here; games keep their own pages too).
export const PRIVACY_URL = 'https://worldofunreal.com/privacy';
export const TERMS_URL = 'https://worldofunreal.com/terms';
// Single sender for the whole org.
export const SENDER_EMAIL = 'no-reply@worldofunreal.com';

// Swappable transport (default: global fetch). Electron hosts inject their
// main-process proxy here so every SDK call flows through it.
let fetchImpl: typeof fetch = (...args) => fetch(...args);
export function setFetchImpl(fn: typeof fetch): void {
  fetchImpl = fn;
}

/** 13+ check. DOB is validated client-side only — never stored or sent. */
export function is13Plus(year: number, month: number, day: number, now = new Date()): boolean {
  const dob = new Date(year, month - 1, day);
  if (Number.isNaN(dob.getTime())) return false;
  const cut = new Date(now.getFullYear() - 13, now.getMonth(), now.getDate());
  return dob <= cut;
}

export type GameContext =
  | 'world_of_unreal'
  | 'shadows_of_war'
  | 'cosmicrafts'
  | 'nftropoly'
  | 'darkrift'
  | string;

export type AuthProvider =
  | 'email'
  | 'google'
  | 'discord'
  | 'twitter'
  | 'meta'
  | 'ethereum'
  | 'solana'
  | 'icp'
  | 'passkey'
  | 'anonymous'
  | string;

export type SocialProvider = 'discord' | 'google' | 'twitter' | 'meta';

export interface EmbeddedWallets {
  evm_address: string;
  solana_address: string;
  icp_principal: string;
  bitcoin_address: string;
}

export interface LinkedIdentity {
  provider: AuthProvider;
  external_id: string;
  linked_at: number;
}

export interface UserProfile {
  avatar_url?: string;
  banner_url?: string;
  country?: string;
  bio?: string;
  is_verified?: boolean;
  custom_attributes?: Record<string, unknown>;
}

export interface CrossGameProfile {
  sow_rank?: string;
  sow_elo?: number;
  sow_matches?: number;
  sow_wins?: number;
  sow_faction?: string;
  cosmicrafts_level?: number;
  cosmicrafts_fleet_power?: number;
  nftropoly_net_worth?: number;
  nftropoly_titles?: number;
}

export interface PlayerAccount {
  id: string;
  username: string;
  display_name: string;
  email?: string;
  newsletter_opt_in: boolean;
  kind: 'human' | 'bot';
  clan_tag?: string;
  clan_name?: string;
  clan_role?: 'owner' | 'elder' | 'member';
  game_stats: CrossGameProfile;
  followers_count: number;
  following_count: number;
  embedded_wallets: EmbeddedWallets;
  linked_identities: LinkedIdentity[];
  profile: UserProfile;
  created_at: number;
  updated_at: number;
}

export interface PlayerSearchResult {
  id: string;
  username: string;
  display_name: string;
  clan_tag?: string;
  avatar_url?: string;
  animal_emoji?: string;
}

export interface Clan {
  tag: string;
  name: string;
  description: string;
  emblem_icon: string;
  created_by: string;
  created_at: number;
  member_count: number;
}

export interface ClanDetails {
  clan: Clan;
  members: Array<{
    account_id: string;
    username: string;
    display_name: string;
    role: 'owner' | 'elder' | 'member';
    joined_at: number;
  }>;
}

export interface AuthResponse {
  status: string;
  account: PlayerAccount;
  session_token: string;
  is_new_account?: boolean;
}

export class WouAuthClient {
  private sessionToken: string | null = null;
  private user: PlayerAccount | null = null;
  private defaultContext: GameContext;

  constructor(defaultContext: GameContext = 'world_of_unreal') {
    this.defaultContext = defaultContext;
    if (typeof window !== 'undefined') {
      this.initSession();
    }
  }

  /** Override the context sent with OTP/QR/OAuth calls (one line per site entry). */
  public setDefaultContext(ctx: GameContext): void {
    this.defaultContext = ctx;
  }

  public initSession(): PlayerAccount | null {
    // 1. Check if returning from cross-domain SSO Hub with token in URL
    const urlParams = new URLSearchParams(window.location.search);
    const tokenFromUrl = urlParams.get('session_token');
    const accParam = urlParams.get('account');

    if (tokenFromUrl && accParam) {
      try {
        const account = JSON.parse(decodeURIComponent(accParam)) as PlayerAccount;
        this.setSession(tokenFromUrl, account);

        // Clean query parameters from address bar cleanly without page refresh
        urlParams.delete('session_token');
        urlParams.delete('account');
        const cleanSearch = urlParams.toString();
        const newUrl = window.location.pathname + (cleanSearch ? `?${cleanSearch}` : '') + window.location.hash;
        window.history.replaceState({}, document.title, newUrl);
        return this.user;
      } catch (err) {
        console.error('Failed to parse returning SSO account payload:', err);
      }
    }

    // 2. Hydrate from localStorage
    const savedToken = localStorage.getItem('wou_session_token');
    const savedUser = localStorage.getItem('wou_user_data');
    if (savedToken && savedUser) {
      try {
        this.sessionToken = savedToken;
        this.user = JSON.parse(savedUser);
      } catch (err) {
        console.error('Failed to parse local stored session:', err);
        this.logout();
      }
    }
    return this.user;
  }

  public loadSession(): PlayerAccount | null {
    if (typeof window !== 'undefined') {
      this.initSession();
    }
    return this.user;
  }

  public setSession(token: string, account: PlayerAccount): void {
    this.sessionToken = token;
    this.user = account;
    if (typeof window !== 'undefined') {
      localStorage.setItem('wou_session_token', token);
      localStorage.setItem('wou_user_data', JSON.stringify(account));
      window.dispatchEvent(
        new CustomEvent('wou:auth-state-change', {
          detail: { authenticated: true, isAuthenticated: true, user: account, token },
        })
      );
    }
  }

  public logout(): void {
    this.sessionToken = null;
    this.user = null;
    if (typeof window !== 'undefined') {
      localStorage.removeItem('wou_session_token');
      localStorage.removeItem('wou_user_data');
      window.dispatchEvent(
        new CustomEvent('wou:auth-state-change', {
          detail: { authenticated: false, isAuthenticated: false, user: null, token: null },
        })
      );
    }
  }

  public getUser(): PlayerAccount | null {
    return this.user;
  }

  public getSessionToken(): string | null {
    return this.sessionToken;
  }

  public isAuthenticated(): boolean {
    return !!this.sessionToken && !!this.user;
  }

  public async getMe(): Promise<PlayerAccount | null> {
    if (!this.sessionToken) return null;
    try {
      const res = await fetchImpl(`${ID_SERVER_URL}/api/v1/auth/me`, {
        headers: { Authorization: `Bearer ${this.sessionToken}` },
      });
      if (!res.ok) return null;
      const account = (await res.json()) as PlayerAccount;
      this.user = account;
      return account;
    } catch {
      return null;
    }
  }

  public async refreshSession(): Promise<AuthResponse | null> {
    if (!this.sessionToken) return null;
    try {
      const res = await fetchImpl(`${ID_SERVER_URL}/api/v1/auth/refresh`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${this.sessionToken}` },
      });
      if (!res.ok) return null;
      const data = (await res.json()) as AuthResponse;
      this.setSession(data.session_token, data.account);
      return data;
    } catch {
      return null;
    }
  }

  // ==========================================
  // QR LOGIN (desktop shows code, authed phone approves)
  // ==========================================

  public async startQr(context?: GameContext | { context?: GameContext; username?: string }): Promise<{ id: string; approve_url: string; secret: string; expires_in_seconds: number; notified?: string[] }> {
    const opts = typeof context === 'object' ? context : { context };
    const res = await fetchImpl(`${ID_SERVER_URL}/api/v1/auth/qr/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ context: opts.context || this.defaultContext, username: opts.username || '' }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to start QR login.');
    return data;
  }

  public async qrStatus(id: string, secret: string): Promise<{ status: string; account?: PlayerAccount; session_token?: string }> {
    const res = await fetchImpl(`${ID_SERVER_URL}/api/v1/auth/qr/${encodeURIComponent(id)}/status`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ secret }),
    });
    const data = await res.json();
    if (res.status === 410) return { status: 'expired' };
    if (!res.ok) throw new Error(data.error || 'QR status check failed.');
    return data;
  }

  public async qrCancel(id: string, secret: string): Promise<void> {
    await fetchImpl(`${ID_SERVER_URL}/api/v1/auth/qr/${encodeURIComponent(id)}/cancel`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ secret }),
    });
  }

  public async botLinkStart(): Promise<{ code: string; expires_in_seconds: number }> {
    if (!this.sessionToken) throw new Error('Sign in first.');
    const res = await fetchImpl(`${ID_SERVER_URL}/api/v1/bots/link/start`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${this.sessionToken}` },
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to mint link code.');
    return data;
  }

  public async botLinked(): Promise<{ telegram: boolean; discord: boolean; telegram_ids: string[]; discord_ids: string[] }> {
    const empty = { telegram: false, discord: false, telegram_ids: [], discord_ids: [] };
    if (!this.sessionToken) return empty;
    try {
      const res = await fetchImpl(`${ID_SERVER_URL}/api/v1/bots/linked`, {
        headers: { Authorization: `Bearer ${this.sessionToken}` },
      });
      if (!res.ok) return empty;
      return await res.json();
    } catch {
      return empty;
    }
  }

  public async botUnlink(ns: 'tg' | 'dc', external_id: string): Promise<void> {
    if (!this.sessionToken) throw new Error('Sign in first.');
    const res = await fetchImpl(`${ID_SERVER_URL}/api/v1/bots/link/${ns}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${this.sessionToken}` },
      body: JSON.stringify({ external_id }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error((data as any).error || 'Unlink failed.');
  }

  public async approveQr(id: string, secret: string): Promise<void> {
    if (!this.sessionToken) throw new Error('Sign in on this device first.');
    const res = await fetchImpl(`${ID_SERVER_URL}/api/v1/auth/qr/${encodeURIComponent(id)}/approve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${this.sessionToken}` },
      body: JSON.stringify({ secret }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error((data as any).error || 'QR approval failed.');
  }

  // ==========================================
  // MODAL CONTROLS
  // ==========================================

  public openModal(): void {
    if (typeof window !== 'undefined') {
      window.dispatchEvent(new CustomEvent('wou:open-auth-modal'));
      const modal = document.getElementById('wou-auth-modal');
      if (modal) modal.classList.remove('hidden');
    }
  }

  public closeModal(): void {
    if (typeof window !== 'undefined') {
      window.dispatchEvent(new CustomEvent('wou:close-auth-modal'));
      const modal = document.getElementById('wou-auth-modal');
      if (modal) modal.classList.add('hidden');
    }
  }

  // ==========================================
  // ANONYMOUS PASS
  // ==========================================

  public async startAnonymous(context?: GameContext, displayName?: string): Promise<AuthResponse> {
    const res = await fetchImpl(`${ID_SERVER_URL}/api/v1/auth/anonymous`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        context: context || this.defaultContext,
        display_name: displayName,
      }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to start anonymous session.');
    this.setSession(data.session_token, data.account);
    this.closeModal();
    return data;
  }

  // ==========================================
  // EMAIL OTP AUTHENTICATION
  // ==========================================

  /** Canonical OTP request used by every modal (web + Hyper). */
  public async requestOtp(email: string, newsletterOptIn = false, context?: GameContext): Promise<{ status: string; message: string }> {
    const res = await fetchImpl(`${ID_SERVER_URL}/api/v1/auth/otp/request`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email,
        account_id: this.user?.id || null,
        context: context || this.defaultContext,
        newsletter_opt_in: newsletterOptIn,
      }),
    });
    const data = await res.json();
    if (!res.ok) throw this.otpError(data);
    return data;
  }

  /** OTP errors carry server payload (retry_after_seconds) for UI cooldowns. */
  private otpError(data: any): Error {
    const err = new Error(data?.error || 'Failed to dispatch verification code.') as any;
    err.data = data ?? null;
    return err;
  }

  /** Human-friendly OTP failure: server message + optional retry wait (seconds). */
  public describeOtpError(err: any): { message: string; retryAfterSeconds?: number } {
    const data = err?.data ?? null;
    const retry = Number(data?.retry_after_seconds ?? NaN);
    const retryAfterSeconds = Number.isFinite(retry) && retry > 0 ? Math.ceil(retry) : undefined;
    let message = String(err?.message || 'Failed to dispatch verification code.');
    if (retryAfterSeconds !== undefined) {
      const m = Math.floor(retryAfterSeconds / 60);
      const s = retryAfterSeconds % 60;
      const wait = m > 0 ? `${m}m ${s}s` : `${s}s`;
      message = `Too many codes requested. Wait ${wait} before trying again.`;
    }
    return retryAfterSeconds === undefined ? { message } : { message, retryAfterSeconds };
  }

  /** Canonical OTP verify used by every modal (web + Hyper). Third arg may be a legacy newsletter boolean (ignored: opt-in is captured at request time). */
  public async verifyOtp(email: string, code: string, context?: GameContext | boolean): Promise<AuthResponse> {
    const res = await fetchImpl(`${ID_SERVER_URL}/api/v1/auth/otp/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email,
        code,
        account_id: this.user?.id || null,
        context: typeof context === 'string' ? context : this.defaultContext,
      }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Invalid or expired verification code.');
    this.setSession(data.session_token, data.account);
    this.closeModal();
    return data;
  }

  // ==========================================
  // SOCIAL OAUTH WITH CENTRALIZED SSO HUB
  // ==========================================

  /**
   * Dispatches user to OAuth Provider using the Centralized World of Unreal Identity Hub.
   * Google/Discord will redirect to https://worldofunreal.com/auth/callback (which is 100% authorized),
   * and the hub will redirect back to this application's current URL with the authenticated session token.
   *
   * Crucial: The provider is serialized inside the `state` JSON payload to avoid domain-isolated sessionStorage loss.
   */
  public loginWithOAuth(provider: SocialProvider): void {
    const returnTo = typeof window !== 'undefined' ? window.location.href : '';
    const accountId = this.user?.id || '';

    if (typeof window !== 'undefined') {
      sessionStorage.setItem('wou_oauth_provider', provider);
    }

    const stateObj = {
      returnTo,
      accountId,
      provider,
    };

    let statePayload = '';
    try {
      statePayload = btoa(unescape(encodeURIComponent(JSON.stringify(stateObj))))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
    } catch {
      statePayload = encodeURIComponent(JSON.stringify(stateObj));
    }

    const targetUrl = `${ID_SERVER_URL}/api/v1/auth/oauth/login/${provider}?redirect_uri=${encodeURIComponent(
      AUTH_HUB_CALLBACK_URL
    )}&state=${encodeURIComponent(statePayload)}`;

    if (typeof window !== 'undefined') {
      window.location.href = targetUrl;
    }
  }

  public loginWithSocial(provider: SocialProvider): void {
    return this.loginWithOAuth(provider);
  }

  public async handleOAuthCallback(provider: string, code: string): Promise<AuthResponse> {
    const res = await fetchImpl(`${ID_SERVER_URL}/api/v1/auth/oauth/callback/${provider}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        code,
        redirect_uri: AUTH_HUB_CALLBACK_URL,
        account_id: this.user?.id || null,
        context: this.defaultContext,
      }),
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'OAuth authentication exchange failed.');
    this.setSession(data.session_token, data.account);
    this.closeModal();
    return data;
  }

  // ==========================================
  // WEB3 AUTHENTICATION (ETHEREUM / SOLANA / ICP)
  // ==========================================

  public async loginWithEthereum(): Promise<AuthResponse> {
    const ethereum = (window as any)?.ethereum;
    if (!ethereum) throw new Error('MetaMask / EVM wallet not detected. Please install MetaMask or compatible wallet.');

    const accounts = await ethereum.request({ method: 'eth_requestAccounts' });
    const publicAddress = accounts[0];

    const challengeRes = await fetchImpl(`${ID_SERVER_URL}/api/v1/auth/web3/challenge`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chain: 'ethereum', public_address: publicAddress }),
    });
    const challengeData = await challengeRes.json();
    if (!challengeRes.ok) throw new Error(challengeData.error || 'Failed to initiate Web3 challenge.');

    const signature = await ethereum.request({
      method: 'personal_sign',
      params: [challengeData.message, publicAddress],
    });

    const verifyRes = await fetchImpl(`${ID_SERVER_URL}/api/v1/auth/web3/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chain: 'ethereum',
        public_address: publicAddress,
        signature,
        message: challengeData.message,
        account_id: this.user?.id || null,
        context: this.defaultContext,
      }),
    });

    const data = await verifyRes.json();
    if (!verifyRes.ok) throw new Error(data.error || 'Ethereum signature verification failed.');
    this.setSession(data.session_token, data.account);
    this.closeModal();
    return data;
  }

  public async loginWithEvm(): Promise<AuthResponse> {
    return this.loginWithEthereum();
  }

  public async loginWithSolana(): Promise<AuthResponse> {
    const phantom = (window as any)?.phantom?.solana || (window as any)?.solana;
    if (!phantom || !phantom.isPhantom) throw new Error('Phantom wallet not detected. Please install Phantom from phantom.app.');

    const connectResp = await phantom.connect();
    const publicAddress = connectResp.publicKey.toString();

    const challengeRes = await fetchImpl(`${ID_SERVER_URL}/api/v1/auth/web3/challenge`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chain: 'solana', public_address: publicAddress }),
    });
    const challengeData = await challengeRes.json();
    if (!challengeRes.ok) throw new Error(challengeData.error || 'Failed to initiate Solana challenge.');

    const messageBytes = new TextEncoder().encode(challengeData.message);
    const signedData = await phantom.signMessage(messageBytes, 'utf8');

    let signatureHex = '';
    if (signedData.signature) {
      const sigArr = Array.from(new Uint8Array(signedData.signature));
      signatureHex = '0x' + sigArr.map((b) => b.toString(16).padStart(2, '0')).join('');
    }

    const verifyRes = await fetchImpl(`${ID_SERVER_URL}/api/v1/auth/web3/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chain: 'solana',
        public_address: publicAddress,
        signature: signatureHex,
        message: challengeData.message,
        account_id: this.user?.id || null,
        context: this.defaultContext,
      }),
    });

    const data = await verifyRes.json();
    if (!verifyRes.ok) throw new Error(data.error || 'Solana signature verification failed.');
    this.setSession(data.session_token, data.account);
    this.closeModal();
    return data;
  }

  public async loginWithInternetIdentity(): Promise<AuthResponse> {
    const { AuthClient } = await import('@dfinity/auth-client');
    const authClient = await AuthClient.create({
      idleOptions: { disableDefaultIdleCallback: true, disableIdle: true },
    });

    return new Promise((resolve, reject) => {
      authClient.login({
        identityProvider: 'https://id.ai/authorize',
        maxTimeToLive: BigInt(8) * BigInt(3_600_000_000_000), // 8 hours
        onSuccess: async () => {
          try {
            const identity = authClient.getIdentity();
            const principal = identity.getPrincipal().toText();

            const challengeRes = await fetchImpl(`${ID_SERVER_URL}/api/v1/auth/web3/challenge`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ chain: 'icp', public_address: principal }),
            });
            const challengeData = await challengeRes.json();
            if (!challengeRes.ok) throw new Error(challengeData.error || 'Failed to challenge ICP identity.');

            const verifyRes = await fetchImpl(`${ID_SERVER_URL}/api/v1/auth/web3/verify`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                chain: 'icp',
                public_address: principal,
                signature: 'ICP_DELEGATION_PROVEN',
                message: challengeData.message,
                account_id: this.user?.id || null,
                context: this.defaultContext,
              }),
            });

            const data = await verifyRes.json();
            if (!verifyRes.ok) throw new Error(data.error || 'Internet Identity verification failed.');
            this.setSession(data.session_token, data.account);
            this.closeModal();
            resolve(data);
          } catch (err: any) {
            reject(new Error(err.message || 'Error completing Internet Identity login.'));
          }
        },
        onError: (err) => {
          reject(new Error(err || 'Internet Identity login cancelled or failed.'));
        },
      });
    });
  }

  public async loginWithIcp(): Promise<AuthResponse> {
    return this.loginWithInternetIdentity();
  }

  // ==========================================
  // WEBAUTHN / PASSKEY AUTHENTICATION
  // ==========================================

  public async loginWithPasskey(): Promise<AuthResponse> {
    if (typeof window === 'undefined' || !window.PublicKeyCredential) {
      throw new Error('WebAuthn / Passkeys are not supported on this browser.');
    }

    const challengeRes = await fetchImpl(`${ID_SERVER_URL}/api/v1/auth/web3/challenge`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chain: 'passkey', public_address: this.user?.username || 'anonymous' }),
    });
    const challengeData = await challengeRes.json();
    if (!challengeRes.ok) throw new Error(challengeData.error || 'Failed to initiate Passkey challenge.');

    const challengeBuffer = Uint8Array.from(atob(challengeData.message.slice(0, 32)), c => c.charCodeAt(0));

    const credential = (await navigator.credentials.get({
      publicKey: {
        challenge: challengeBuffer,
        timeout: 60000,
        userVerification: 'preferred',
      },
    })) as PublicKeyCredential;

    if (!credential) throw new Error('Passkey authentication cancelled or failed.');

    const verifyRes = await fetchImpl(`${ID_SERVER_URL}/api/v1/auth/web3/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chain: 'passkey',
        public_address: credential.id,
        signature: 'PASSKEY_ASSERTION_VERIFIED',
        message: challengeData.message,
        account_id: this.user?.id || null,
        context: this.defaultContext,
      }),
    });

    const data = await verifyRes.json();
    if (!verifyRes.ok) throw new Error(data.error || 'Passkey verification failed.');
    this.setSession(data.session_token, data.account);
    this.closeModal();
    return data;
  }

  // ==========================================
  // PLAYER SEARCH & CLANS
  // ==========================================

  public async searchPlayers(query: string, limit: number = 10): Promise<PlayerSearchResult[]> {
    const clean = query.trim();
    if (!clean) return [];
    try {
      const res = await fetchImpl(`${ID_SERVER_URL}/api/v1/user/search?q=${encodeURIComponent(clean)}&limit=${limit}`);
      if (!res.ok) return [];
      return await res.json();
    } catch {
      return [];
    }
  }

  public async getClans(limit: number = 20): Promise<Clan[]> {
    try {
      const res = await fetchImpl(`${ID_SERVER_URL}/api/v1/clans/list?limit=${limit}`);
      if (!res.ok) return [];
      return await res.json();
    } catch {
      return [];
    }
  }

  public async getClanDetails(tag: string): Promise<ClanDetails | null> {
    try {
      const res = await fetchImpl(`${ID_SERVER_URL}/api/v1/clans/${encodeURIComponent(tag)}`);
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  }

  public async getClan(tag: string): Promise<ClanDetails | null> {
    return this.getClanDetails(tag);
  }

  public async createClan(tag: string, name: string, description: string, emblemIcon: string = '🛡️'): Promise<Clan> {
    if (!this.sessionToken) throw new Error('Authentication required to form a clan.');
    const res = await fetchImpl(`${ID_SERVER_URL}/api/v1/clans/create`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${this.sessionToken}`,
      },
      body: JSON.stringify({ tag, name, description, emblem_icon: emblemIcon }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to create clan.');
    if (this.user) {
      this.user.clan_tag = tag;
      this.user.clan_role = 'owner';
      this.setSession(this.sessionToken, this.user);
    }
    return data;
  }

  public async joinClan(tag: string): Promise<{ status: string }> {
    if (!this.sessionToken) throw new Error('Authentication required to join clan.');
    const res = await fetchImpl(`${ID_SERVER_URL}/api/v1/clans/${encodeURIComponent(tag)}/join`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${this.sessionToken}`,
      },
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to join clan.');
    if (this.user) {
      this.user.clan_tag = tag;
      this.user.clan_role = 'member';
      this.setSession(this.sessionToken, this.user);
    }
    return data;
  }

  public async leaveClan(tag: string): Promise<{ status: string }> {
    if (!this.sessionToken) throw new Error('Authentication required to leave clan.');
    const res = await fetchImpl(`${ID_SERVER_URL}/api/v1/clans/${encodeURIComponent(tag)}/leave`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${this.sessionToken}`,
      },
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to leave clan.');
    if (this.user) {
      this.user.clan_tag = undefined;
      this.user.clan_role = undefined;
      this.setSession(this.sessionToken, this.user);
    }
    return data;
  }

  public async getFeed(limit: number = 20): Promise<any[]> {
    if (!this.sessionToken) return [];
    const res = await fetchImpl(`${ID_SERVER_URL}/api/v1/social/feed?limit=${limit}`, {
      headers: { Authorization: `Bearer ${this.sessionToken}` },
    });
    if (!res.ok) return [];
    return res.json();
  }

  public async follow(id: string): Promise<void> {
    if (!this.sessionToken) throw new Error('Authentication required to follow.');
    const res = await fetchImpl(`${ID_SERVER_URL}/api/v1/social/follow/${encodeURIComponent(id)}`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${this.sessionToken}` },
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to follow.');
  }

  public async unfollow(id: string): Promise<void> {
    if (!this.sessionToken) throw new Error('Authentication required to unfollow.');
    const res = await fetchImpl(`${ID_SERVER_URL}/api/v1/social/unfollow/${encodeURIComponent(id)}`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${this.sessionToken}` },
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to unfollow.');
  }

  public async getUserByUsername(username: string): Promise<PlayerAccount | null> {
    const clean = username.trim().replace(/^@/, '');
    if (!clean) return null;
    try {
      const res = await fetchImpl(`${ID_SERVER_URL}/api/v1/user/by-username/${encodeURIComponent(clean)}`);
      if (!res.ok) return null;
      return (await res.json()) as PlayerAccount;
    } catch {
      return null;
    }
  }

  public async checkUsername(username: string): Promise<{ username: string; available: boolean }> {
    const clean = username.trim().replace(/^@/, '');
    const res = await fetchImpl(`${ID_SERVER_URL}/api/v1/user/check-username/${encodeURIComponent(clean)}`);
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to check username.');
    return data as { username: string; available: boolean };
  }

  public async updateProfile(input: {
    display_name?: string;
    username?: string;
    bio?: string;
    avatar_url?: string;
    banner_url?: string;
    country?: string;
  }): Promise<PlayerAccount> {
    if (!this.sessionToken || !this.user) throw new Error('Authentication required to update profile.');
    const res = await fetchImpl(`${ID_SERVER_URL}/api/v1/user/profile/${encodeURIComponent(this.user.id)}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${this.sessionToken}`,
      },
      body: JSON.stringify(input),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to update profile.');
    this.setSession(this.sessionToken, data as PlayerAccount);
    return data as PlayerAccount;
  }

  public async uploadMedia(
    blob: Blob,
    mediaType: 'avatar' | 'banner',
  ): Promise<{ url: string; media_type: string; account: PlayerAccount }> {
    if (!this.sessionToken) throw new Error('Authentication required to upload media.');
    const form = new FormData();
    form.append('file', blob, `${mediaType}.webp`);
    form.append('media_type', mediaType);
    const res = await fetchImpl(`${ID_SERVER_URL}/api/v1/user/upload-media`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${this.sessionToken}` },
      body: form,
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to upload media.');
    if (data.account) this.setSession(this.sessionToken, data.account as PlayerAccount);
    return data as { url: string; media_type: string; account: PlayerAccount };
  }

  /** Opens the profile editor. The host app renders the modal (worldofunreal.com listens for this). */
  public openEditProfileModal(): void {
    if (typeof window !== 'undefined') {
      window.dispatchEvent(new CustomEvent('wou:open-edit-profile-modal'));
    }
  }
}

export const wouAuth = new WouAuthClient();
