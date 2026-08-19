export type GameContext =
  | 'shadowsofwar'
  | 'cosmicrafts'
  | 'nftropoly'
  | 'darkrift'
  | 'worldofunreal';

export type AuthProvider =
  | 'email'
  | 'crazygames'
  | 'poki'
  | 'google'
  | 'apple'
  | 'ethereum'
  | 'solana'
  | string;

export interface LinkedIdentity {
  provider: AuthProvider;
  external_id: string;
  linked_at: number;
}

export interface UserProfile {
  avatar_url?: string;
  country?: string;
  bio?: string;
  custom_attributes?: Record<string, unknown>;
}

export interface PlayerAccount {
  id: string;
  display_name: string;
  email?: string;
  newsletter_opt_in: boolean;
  kind: 'human' | 'bot';
  linked_identities: LinkedIdentity[];
  profile: UserProfile;
  created_at: number;
  updated_at: number;
}

export interface AuthResponse {
  account: PlayerAccount;
  session_token: string;
}

export interface OtpVerifyResponse {
  status: string;
  account: PlayerAccount;
  session_token: string;
  is_new_account: boolean;
}

export class WouIdClient {
  private baseUrl: string;
  private storageKey: string;

  constructor(options?: { baseUrl?: string; storageKey?: string }) {
    this.baseUrl = (options?.baseUrl || 'https://id.worldofunreal.com').replace(/\/+$/, '');
    this.storageKey = options?.storageKey || 'wou_account_id';
  }

  /**
   * Step 0: Start or restore an anonymous player session (Zero Friction).
   * Automatically persists account ID to localStorage if available.
   */
  async startAnonymous(
    context: GameContext = 'worldofunreal',
    displayName?: string
  ): Promise<AuthResponse> {
    let storedId: string | null = null;
    if (typeof window !== 'undefined' && window.localStorage) {
      storedId = window.localStorage.getItem(this.storageKey);
    }

    const res = await fetch(`${this.baseUrl}/api/v1/auth/anonymous`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        account_id: storedId || undefined,
        display_name: displayName,
        context,
      }),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: 'Unknown error' }));
      throw new Error(err.error || `HTTP ${res.status}`);
    }

    const data: AuthResponse = await res.json();
    if (typeof window !== 'undefined' && window.localStorage) {
      window.localStorage.setItem(this.storageKey, data.account.id);
      window.localStorage.setItem('wou_session_token', data.session_token);
    }

    return data;
  }

  /**
   * Step 1: Request 6-digit OTP code sent via Stalwart to player's email.
   */
  async requestOtp(
    email: string,
    context: GameContext = 'worldofunreal',
    newsletterOptIn = true
  ): Promise<{ status: string; expires_in_seconds: number }> {
    let accountId: string | null = null;
    if (typeof window !== 'undefined' && window.localStorage) {
      accountId = window.localStorage.getItem(this.storageKey);
    }

    const res = await fetch(`${this.baseUrl}/api/v1/auth/otp/request`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email,
        account_id: accountId || undefined,
        context,
        newsletter_opt_in: newsletterOptIn,
      }),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: 'Unknown error' }));
      throw new Error(err.error || `HTTP ${res.status}`);
    }

    return res.json();
  }

  /**
   * Step 2: Verify 6-digit OTP code, link email, and promote account to permanent.
   */
  async verifyOtp(
    email: string,
    code: string,
    context: GameContext = 'worldofunreal'
  ): Promise<OtpVerifyResponse> {
    let accountId: string | null = null;
    if (typeof window !== 'undefined' && window.localStorage) {
      accountId = window.localStorage.getItem(this.storageKey);
    }

    const res = await fetch(`${this.baseUrl}/api/v1/auth/otp/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email,
        code,
        account_id: accountId || undefined,
        context,
      }),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: 'Invalid or expired code' }));
      throw new Error(err.error || `HTTP ${res.status}`);
    }

    const data: OtpVerifyResponse = await res.json();
    if (typeof window !== 'undefined' && window.localStorage) {
      window.localStorage.setItem(this.storageKey, data.account.id);
      window.localStorage.setItem('wou_session_token', data.session_token);
    }

    return data;
  }

  /**
   * Link CrazyGames player token.
   */
  async linkCrazyGames(token: string, context: GameContext = 'worldofunreal'): Promise<PlayerAccount> {
    const accountId = this.getStoredAccountId();
    const res = await fetch(`${this.baseUrl}/api/v1/auth/link/crazygames`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ account_id: accountId, token, context }),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: 'Failed to link CrazyGames' }));
      throw new Error(err.error || `HTTP ${res.status}`);
    }

    const data = await res.json();
    return data.account;
  }

  /**
   * Link Ethereum (EVM) Wallet with SIWE signature.
   */
  async linkEthereum(
    address: string,
    message: string,
    signature: string,
    context: GameContext = 'worldofunreal'
  ): Promise<PlayerAccount> {
    const accountId = this.getStoredAccountId();
    const res = await fetch(`${this.baseUrl}/api/v1/auth/link/ethereum`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        account_id: accountId,
        address_or_pubkey: address,
        message,
        signature,
        context,
      }),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: 'Failed to link Ethereum wallet' }));
      throw new Error(err.error || `HTTP ${res.status}`);
    }

    const data = await res.json();
    return data.account;
  }

  /**
   * Link Solana Wallet with SIWS signature.
   */
  async linkSolana(
    pubkey: string,
    message: string,
    signature: string,
    context: GameContext = 'worldofunreal'
  ): Promise<PlayerAccount> {
    const accountId = this.getStoredAccountId();
    const res = await fetch(`${this.baseUrl}/api/v1/auth/link/solana`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        account_id: accountId,
        address_or_pubkey: pubkey,
        message,
        signature,
        context,
      }),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: 'Failed to link Solana wallet' }));
      throw new Error(err.error || `HTTP ${res.status}`);
    }

    const data = await res.json();
    return data.account;
  }

  /**
   * Update Player display name.
   */
  async updateDisplayName(displayName: string): Promise<PlayerAccount> {
    const accountId = this.getStoredAccountId();
    const res = await fetch(`${this.baseUrl}/api/v1/user/profile/${accountId}/name`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ display_name: displayName }),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: 'Failed to update name' }));
      throw new Error(err.error || `HTTP ${res.status}`);
    }

    return res.json();
  }

  private getStoredAccountId(): string {
    if (typeof window !== 'undefined' && window.localStorage) {
      const id = window.localStorage.getItem(this.storageKey);
      if (id) return id;
    }
    throw new Error('No active account ID found in local storage. Call startAnonymous() first.');
  }
}
