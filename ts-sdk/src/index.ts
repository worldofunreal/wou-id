/**
 * World of Unreal Universal Identity & Cross-Game SDK
 * (C) 2026 World of Unreal. MIT License.
 */

export const ID_SERVER_URL = 'https://id.worldofunreal.com';
export const AUTH_HUB_CALLBACK_URL = 'https://worldofunreal.com/auth/callback';

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
  btc_bech32_address?: string;
  derived_at: number;
}

export interface LinkedIdentity {
  provider: AuthProvider;
  external_id: string;
  linked_at: number;
}

export interface UserProfile {
  avatar_url?: string;
  avatar_id?: string;
  noble_animal?: string;
  country?: string;
  bio?: string;
  custom_attributes?: Record<string, unknown>;
}

export interface CrossGameStats {
  sow_rank?: string;
  sow_elo?: number;
  cosmic_fleet_power?: number;
  nftropoly_wealth_index?: number;
  total_matches_played?: number;
}

export interface PlayerAccount {
  id: string;
  username: string;
  display_name: string;
  email?: string;
  newsletter_opt_in: boolean;
  kind: 'human' | 'bot';
  clan_tag?: string;
  clan_role?: 'owner' | 'elder' | 'member';
  stats: CrossGameStats;
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
  noble_animal?: string;
  sow_elo?: number;
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

  private initSession(): void {
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
        return;
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
  }

  public setSession(token: string, account: PlayerAccount): void {
    this.sessionToken = token;
    this.user = account;
    if (typeof window !== 'undefined') {
      localStorage.setItem('wou_session_token', token);
      localStorage.setItem('wou_user_data', JSON.stringify(account));
      window.dispatchEvent(
        new CustomEvent('wou:auth-state-change', {
          detail: { authenticated: true, user: account, token },
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
          detail: { authenticated: false, user: null, token: null },
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
    const res = await fetch(`${ID_SERVER_URL}/api/v1/auth/anonymous`, {
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

  public async sendEmailOtp(email: string): Promise<{ status: string; message: string }> {
    const res = await fetch(`${ID_SERVER_URL}/api/v1/auth/otp/send`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to dispatch verification code.');
    return data;
  }

  public async verifyEmailOtp(email: string, code: string, context?: GameContext): Promise<AuthResponse> {
    const res = await fetch(`${ID_SERVER_URL}/api/v1/auth/otp/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email,
        code,
        account_id: this.user?.id || null,
        context: context || this.defaultContext,
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
   */
  public loginWithOAuth(provider: SocialProvider): void {
    const returnTo = typeof window !== 'undefined' ? window.location.href : '';
    const accountId = this.user?.id || '';

    if (typeof window !== 'undefined') {
      sessionStorage.setItem('wou_oauth_provider', provider);
    }

    const targetUrl = `${ID_SERVER_URL}/api/v1/auth/oauth/login/${provider}?redirect_uri=${encodeURIComponent(
      AUTH_HUB_CALLBACK_URL
    )}&state=${encodeURIComponent(JSON.stringify({ returnTo, accountId }))}`;

    if (typeof window !== 'undefined') {
      window.location.href = targetUrl;
    }
  }

  public loginWithSocial(provider: SocialProvider): void {
    return this.loginWithOAuth(provider);
  }

  public async handleOAuthCallback(provider: string, code: string): Promise<AuthResponse> {
    const res = await fetch(`${ID_SERVER_URL}/api/v1/auth/oauth/callback/${provider}`, {
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

    const challengeRes = await fetch(`${ID_SERVER_URL}/api/v1/auth/web3/challenge`, {
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

    const verifyRes = await fetch(`${ID_SERVER_URL}/api/v1/auth/web3/verify`, {
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

    const challengeRes = await fetch(`${ID_SERVER_URL}/api/v1/auth/web3/challenge`, {
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

    const verifyRes = await fetch(`${ID_SERVER_URL}/api/v1/auth/web3/verify`, {
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

            const challengeRes = await fetch(`${ID_SERVER_URL}/api/v1/auth/web3/challenge`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ chain: 'icp', public_address: principal }),
            });
            const challengeData = await challengeRes.json();
            if (!challengeRes.ok) throw new Error(challengeData.error || 'Failed to challenge ICP identity.');

            const verifyRes = await fetch(`${ID_SERVER_URL}/api/v1/auth/web3/verify`, {
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
  // PLAYER SEARCH & CLANS
  // ==========================================

  public async searchPlayers(query: string, limit: number = 10): Promise<PlayerSearchResult[]> {
    const clean = query.trim();
    if (!clean) return [];
    try {
      const res = await fetch(`${ID_SERVER_URL}/api/v1/user/search?q=${encodeURIComponent(clean)}&limit=${limit}`);
      if (!res.ok) return [];
      return await res.json();
    } catch {
      return [];
    }
  }

  public async getClans(limit: number = 20): Promise<Clan[]> {
    try {
      const res = await fetch(`${ID_SERVER_URL}/api/v1/clans/list?limit=${limit}`);
      if (!res.ok) return [];
      return await res.json();
    } catch {
      return [];
    }
  }

  public async getClanDetails(tag: string): Promise<ClanDetails | null> {
    try {
      const res = await fetch(`${ID_SERVER_URL}/api/v1/clans/${encodeURIComponent(tag)}`);
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  }

  public async createClan(tag: string, name: string, description: string, emblemIcon: string = '🛡️'): Promise<Clan> {
    if (!this.sessionToken) throw new Error('Authentication required to form a clan.');
    const res = await fetch(`${ID_SERVER_URL}/api/v1/clans/create`, {
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
    const res = await fetch(`${ID_SERVER_URL}/api/v1/clans/${encodeURIComponent(tag)}/join`, {
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
    const res = await fetch(`${ID_SERVER_URL}/api/v1/clans/${encodeURIComponent(tag)}/leave`, {
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
}

export const wouAuth = new WouAuthClient();
