import React, { useState } from 'react';
import {
  AlertCircle,
  CheckCircle2,
  KeyRound,
  Lock,
  QrCode,
  ShieldCheck,
  UserCheck,
} from 'lucide-react';
import type { AuthStatusResponse, SessionInfo } from '../shared/types';
import { api, ApiError } from '../lib/api';

interface LoginViewProps {
  authStatus: AuthStatusResponse;
  initialNotice?: string | null;
  onAuthenticated: (session: SessionInfo) => void;
  onBootstrapComplete: () => Promise<void>;
  onOpenPublicVerify: () => void;
}

type AuthTab = 'maker' | 'admin';

export const LoginView: React.FC<LoginViewProps> = ({
  authStatus,
  initialNotice,
  onAuthenticated,
  onBootstrapComplete,
  onOpenPublicVerify,
}) => {
  const [activeTab, setActiveTab] = useState<AuthTab>('maker');

  // Maker Login state
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');

  // Main Core Admin Unlock state
  const [adminPassword, setAdminPassword] = useState('');

  // First-Run Security Setup state
  const [setupUsername, setSetupUsername] = useState('user-pscrappers');
  const [setupMakerPassword, setSetupMakerPassword] = useState('');
  const [setupMainAdminPassword, setSetupMainAdminPassword] = useState('');
  const [setupProtectedPassword, setSetupProtectedPassword] = useState('');

  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(initialNotice ?? null);

  const handleMakerLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setNotice(null);
    setSubmitting(true);
    try {
      const session = await api.loginMaker(username, password);
      onAuthenticated(session);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Unable to sign in. Please try again.');
    } finally {
      setSubmitting(false);
    }
  };

  const handleAdminUnlock = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setNotice(null);
    setSubmitting(true);
    try {
      const session = await api.unlockMainAdmin(adminPassword);
      onAuthenticated(session);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Main Core Admin unlock failed.');
    } finally {
      setSubmitting(false);
    }
  };

  const handleBootstrap = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setNotice(null);
    setSubmitting(true);
    try {
      const result = await api.bootstrapSecurity({
        makerUsername: setupUsername,
        makerPassword: setupMakerPassword,
        mainAdminPassword: setupMainAdminPassword,
        protectedPassword: setupProtectedPassword,
      });
      setUsername(result.makerUsername);
      setNotice('Security credentials initialized with salted scrypt hashes. Sign in below.');
      await onBootstrapComplete();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Security setup failed.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-50 flex flex-col">
      {/* Clean 3-Zone Top Bar */}
      <header className="bg-white border-b border-slate-200 px-6 py-4">
        <div className="max-w-6xl mx-auto flex items-center justify-between gap-8">
          <div className="flex items-center gap-3 whitespace-nowrap shrink-0">
            <div className="w-9 h-9 rounded-lg bg-[#0B1F3A] text-white flex items-center justify-center font-display font-bold text-sm">
              PS
            </div>
            <span className="font-display font-bold text-lg text-[#0B1F3A] tracking-tight">
              Parivahan Scrappers
            </span>
          </div>

          <nav className="hidden md:flex items-center gap-6 text-sm font-medium text-slate-600">
            <span className="whitespace-nowrap shrink-0 text-slate-900">Registry Portal</span>
            <button
              type="button"
              onClick={onOpenPublicVerify}
              className="hover:text-[#0B1F3A] transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              Public QR Verification
            </button>
          </nav>

          <div className="shrink-0">
            <button
              type="button"
              onClick={onOpenPublicVerify}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold text-[#0B1F3A] border border-slate-300 bg-white hover:bg-slate-50 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              <QrCode className="w-4 h-4 text-[#059669]" />
              Verify Certificate
            </button>
          </div>
        </div>
      </header>

      {/* Main Split Portal */}
      <main className="flex-1 flex items-center justify-center px-6 py-10">
        <div className="w-full max-w-5xl grid grid-cols-1 lg:grid-cols-12 bg-white border border-slate-200 rounded-xl overflow-hidden shadow-sm">
          {/* Left Institutional Branding Panel */}
          <section className="lg:col-span-5 bg-[#0B1F3A] text-white p-8 lg:p-10 flex flex-col justify-between">
            <div>
              <p className="text-xs font-medium text-emerald-300 tracking-wide mb-3">
                Authorized RVSF Certificate Registry
              </p>
              <h1 className="font-display text-2xl lg:text-3xl font-bold leading-tight text-balance">
                Vehicle Scrapping Certificate Management
              </h1>
              <p className="mt-4 text-sm text-slate-300 leading-relaxed">
                Dedicated fresh registry for issuing tamper-evident scrapping certificates,
                generating cryptographic reference numbers, and enabling instant public QR
                verification.
              </p>

              <div className="mt-8 pt-6 border-t border-white/10 space-y-4 text-sm">
                <div>
                  <p className="font-semibold text-white">Role-Separated Access</p>
                  <p className="text-xs text-slate-300 mt-0.5">
                    Certificate Makers issue certificates and view only the latest five records.
                    Full registry governance requires Main Core Admin unlock.
                  </p>
                </div>
                <div>
                  <p className="font-semibold text-white">Cryptographic Uniqueness</p>
                  <p className="text-xs text-slate-300 mt-0.5 font-mono">
                    PS/YY/R[7-Digit] · REG-C[6-Digit] · SHA-256 Digest
                  </p>
                </div>
                <div>
                  <p className="font-semibold text-white">Zero Historical Leakage</p>
                  <p className="text-xs text-slate-300 mt-0.5">
                    Clean independent registry starting from zero certificates with atomic number
                    reservations and immutable audit logging.
                  </p>
                </div>
              </div>
            </div>

            <div className="mt-10 pt-5 border-t border-white/10 text-xs text-slate-400">
              <span>{authStatus.facilityName}</span>
              <span className="mx-2">·</span>
              <span>
                {authStatus.storageMode === 'firestore'
                  ? `Firestore (${authStatus.firestoreProjectId})`
                  : authStatus.storageMode === 'firestore_unconfigured'
                    ? 'Awaiting Vercel Firestore Env Vars'
                    : 'Local Dev Staging Memory'}
              </span>
            </div>
          </section>

          {/* Right Auth Form Panel */}
          <section className="lg:col-span-7 p-8 lg:p-10 flex flex-col justify-center">
            {authStatus.storageMode === 'firestore_unconfigured' && (
              <div className="mb-6 p-4 rounded-lg bg-amber-50 border border-amber-200 text-amber-950 text-xs space-y-1.5">
                <p className="font-semibold text-sm">
                  Production Firestore Configuration Required
                </p>
                <p>
                  This Vercel deployment refuses ephemeral writes until your fresh Google Cloud
                  Firestore service account variables are configured in Vercel Project Settings:
                </p>
                <p className="font-mono text-amber-900">
                  {(authStatus.missingFirestoreEnvVars ?? [
                    'FIREBASE_PROJECT_ID',
                    'FIREBASE_CLIENT_EMAIL',
                    'FIREBASE_PRIVATE_KEY',
                  ]).join(', ')}
                </p>
              </div>
            )}

            {error && (
              <div
                role="alert"
                className="mb-6 flex items-start gap-3 p-3.5 rounded-lg bg-red-50 border border-red-200 text-red-800 text-sm"
              >
                <AlertCircle className="w-4 h-4 shrink-0 mt-0.5 text-red-600" />
                <span>{error}</span>
              </div>
            )}

            {notice && (
              <div className="mb-6 flex items-start gap-3 p-3.5 rounded-lg bg-emerald-50 border border-emerald-200 text-emerald-900 text-sm">
                <CheckCircle2 className="w-4 h-4 shrink-0 mt-0.5 text-emerald-600" />
                <span>{notice}</span>
              </div>
            )}

            {authStatus.requiresBootstrap ? (
              <div>
                <h2 className="font-display text-xl font-bold text-[#0B1F3A]">
                  First-Run Security Initialization
                </h2>
                <p className="text-sm text-slate-600 mt-1.5 leading-relaxed">
                  No server environment credentials were detected yet. Set your initial role
                  passwords below to lock and activate this fresh registry. All passwords are
                  hashed server-side with salted scrypt. For Vercel production, configure the
                  corresponding environment variables directly in Vercel Project Settings.
                </p>

                <form onSubmit={handleBootstrap} className="mt-6 space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-slate-700 mb-1.5">
                      Certificate Maker Username
                    </label>
                    <input
                      type="text"
                      required
                      minLength={3}
                      value={setupUsername}
                      onChange={(e) => setSetupUsername(e.target.value)}
                      placeholder="pscrappers"
                      className="w-full px-3.5 py-2.5 rounded-lg border border-slate-300 text-sm focus:outline-none focus:ring-2 focus:ring-[#059669] focus:border-[#059669]"
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-slate-700 mb-1.5">
                      Certificate Maker Password
                    </label>
                    <input
                      type="password"
                      required
                      minLength={8}
                      value={setupMakerPassword}
                      onChange={(e) => setSetupMakerPassword(e.target.value)}
                      placeholder="Minimum 8 characters"
                      className="w-full px-3.5 py-2.5 rounded-lg border border-slate-300 text-sm focus:outline-none focus:ring-2 focus:ring-[#059669] focus:border-[#059669]"
                    />
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-medium text-slate-700 mb-1.5">
                        Main Core Admin Password
                      </label>
                      <input
                        type="password"
                        required
                        minLength={8}
                        value={setupMainAdminPassword}
                        onChange={(e) => setSetupMainAdminPassword(e.target.value)}
                        placeholder="Separate admin password"
                        className="w-full px-3.5 py-2.5 rounded-lg border border-slate-300 text-sm focus:outline-none focus:ring-2 focus:ring-[#059669] focus:border-[#059669]"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-slate-700 mb-1.5">
                        Protected Edit / Delete Password
                      </label>
                      <input
                        type="password"
                        required
                        minLength={8}
                        value={setupProtectedPassword}
                        onChange={(e) => setSetupProtectedPassword(e.target.value)}
                        placeholder="Separate action password"
                        className="w-full px-3.5 py-2.5 rounded-lg border border-slate-300 text-sm focus:outline-none focus:ring-2 focus:ring-[#059669] focus:border-[#059669]"
                      />
                    </div>
                  </div>

                  <button
                    type="submit"
                    disabled={submitting}
                    className="w-full mt-2 py-2.5 px-4 rounded-lg bg-[#059669] hover:bg-[#047857] text-white font-semibold text-sm transition-colors disabled:opacity-50 cursor-pointer"
                  >
                    {submitting ? 'Initializing Security...' : 'Initialize Fresh Registry Credentials'}
                  </button>
                </form>
              </div>
            ) : (
              <div>
                {/* Segmented Role Switcher */}
                <div className="grid grid-cols-2 gap-1 p-1 bg-slate-100 rounded-lg mb-6">
                  <button
                    type="button"
                    onClick={() => {
                      setActiveTab('maker');
                      setError(null);
                    }}
                    className={`flex items-center justify-center gap-2 py-2 px-3 rounded-md text-sm font-semibold transition-colors cursor-pointer whitespace-nowrap ${
                      activeTab === 'maker'
                        ? 'bg-white text-[#0B1F3A] shadow-sm'
                        : 'text-slate-600 hover:text-slate-900'
                    }`}
                  >
                    <UserCheck className="w-4 h-4 text-[#059669]" />
                    Certificate Maker
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setActiveTab('admin');
                      setError(null);
                    }}
                    className={`flex items-center justify-center gap-2 py-2 px-3 rounded-md text-sm font-semibold transition-colors cursor-pointer whitespace-nowrap ${
                      activeTab === 'admin'
                        ? 'bg-white text-[#0B1F3A] shadow-sm'
                        : 'text-slate-600 hover:text-slate-900'
                    }`}
                  >
                    <ShieldCheck className="w-4 h-4 text-[#0B1F3A]" />
                    Main Core Admin
                  </button>
                </div>

                {activeTab === 'maker' ? (
                  <form onSubmit={handleMakerLogin} className="space-y-4">
                    <div>
                      <h2 className="font-display text-xl font-bold text-[#0B1F3A]">
                        Certificate Maker Sign In
                      </h2>
                      <p className="text-sm text-slate-600 mt-1">
                        Sign in to issue new vehicle scrapping certificates and access the latest
                        five records.
                      </p>
                    </div>

                    <div className="pt-2">
                      <label className="block text-sm font-medium text-slate-700 mb-1.5">
                        Username
                      </label>
                      <input
                        type="text"
                        required
                        autoComplete="username"
                        value={username}
                        onChange={(e) => setUsername(e.target.value)}
                        placeholder="Enter Maker username"
                        className="w-full px-3.5 py-2.5 rounded-lg border border-slate-300 text-sm focus:outline-none focus:ring-2 focus:ring-[#059669] focus:border-[#059669]"
                      />
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-slate-700 mb-1.5">
                        Password
                      </label>
                      <input
                        type="password"
                        required
                        autoComplete="current-password"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        placeholder="Enter Maker password"
                        className="w-full px-3.5 py-2.5 rounded-lg border border-slate-300 text-sm focus:outline-none focus:ring-2 focus:ring-[#059669] focus:border-[#059669]"
                      />
                    </div>

                    <button
                      type="submit"
                      disabled={submitting}
                      className="w-full py-2.5 px-4 rounded-lg bg-[#0B1F3A] hover:bg-[#132f57] text-white font-semibold text-sm transition-colors flex items-center justify-center gap-2 disabled:opacity-50 cursor-pointer"
                    >
                      <Lock className="w-4 h-4" />
                      {submitting ? 'Authenticating...' : 'Sign In as Certificate Maker'}
                    </button>
                  </form>
                ) : (
                  <form onSubmit={handleAdminUnlock} className="space-y-4">
                    <div>
                      <h2 className="font-display text-xl font-bold text-[#0B1F3A]">
                        Main Core Admin Unlock
                      </h2>
                      <p className="text-sm text-slate-600 mt-1">
                        Separate administrative unlock for full registry access, statistics,
                        protected actions, audit logs, backups, and settings.
                      </p>
                    </div>

                    <div className="pt-2">
                      <label className="block text-sm font-medium text-slate-700 mb-1.5">
                        Main Core Admin Password
                      </label>
                      <input
                        type="password"
                        required
                        autoComplete="current-password"
                        value={adminPassword}
                        onChange={(e) => setAdminPassword(e.target.value)}
                        placeholder="Enter Main Core Admin password"
                        className="w-full px-3.5 py-2.5 rounded-lg border border-slate-300 text-sm focus:outline-none focus:ring-2 focus:ring-[#059669] focus:border-[#059669]"
                      />
                    </div>

                    <button
                      type="submit"
                      disabled={submitting}
                      className="w-full py-2.5 px-4 rounded-lg bg-[#059669] hover:bg-[#047857] text-white font-semibold text-sm transition-colors flex items-center justify-center gap-2 disabled:opacity-50 cursor-pointer"
                    >
                      <KeyRound className="w-4 h-4" />
                      {submitting ? 'Verifying...' : 'Unlock Main Core Admin Console'}
                    </button>
                  </form>
                )}

                <div className="mt-6 pt-5 border-t border-slate-200 flex items-center justify-between text-xs text-slate-500">
                  <span>Need to verify a scrapping certificate?</span>
                  <button
                    type="button"
                    onClick={onOpenPublicVerify}
                    className="font-semibold text-[#059669] hover:text-[#047857] cursor-pointer"
                  >
                    Open Public Verification
                  </button>
                </div>
              </div>
            )}
          </section>
        </div>
      </main>
    </div>
  );
};
