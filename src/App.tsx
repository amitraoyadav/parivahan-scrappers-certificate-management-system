import React, { useCallback, useEffect, useState } from 'react';
import {
  AlertCircle,
  CheckCircle2,
  KeyRound,
  LogOut,
  QrCode,
  ShieldCheck,
  UserCheck,
  X,
} from 'lucide-react';
import type { AuthStatusResponse, CertificateRecord, SessionInfo } from './shared/types';
import { api, ApiError, setMemoryToken } from './lib/api';
import { AdminDashboard } from './components/AdminDashboard';
import { CertificatePreviewModal } from './components/CertificatePreviewModal';
import { CreateCertificateForm } from './components/CreateCertificateForm';
import { LoginView } from './components/LoginView';
import { MakerEditCertificateModal } from './components/MakerEditCertificateModal';
import { PublicVerifyView } from './components/PublicVerifyView';
import { RecentCertificatesPanel } from './components/RecentCertificatesPanel';

interface RouteState {
  isVerifyRoute: boolean;
  certNumber: string;
  token: string;
}

function parseRoute(): RouteState {
  const pathname = window.location.pathname;
  const params = new URLSearchParams(window.location.search);
  const certNumber = params.get('certificateNumber') || '';
  const token = params.get('token') || '';
  const isVerifyRoute = pathname === '/verify' || Boolean(certNumber);
  return { isVerifyRoute, certNumber, token };
}

export default function App() {
  const [route, setRoute] = useState<RouteState>(parseRoute);
  const [authStatus, setAuthStatus] = useState<AuthStatusResponse | null>(null);
  const [session, setSession] = useState<SessionInfo | null>(null);
  const [loadingAuth, setLoadingAuth] = useState(true);

  // Maker workspace state
  const [recentCertificates, setRecentCertificates] = useState<CertificateRecord[]>([]);
  const [loadingRecent, setLoadingRecent] = useState(false);
  const [makerNotice, setMakerNotice] = useState<string | null>(null);
  const [sessionExpiredNotice, setSessionExpiredNotice] = useState<string | null>(null);

  // Modals
  const [previewCert, setPreviewCert] = useState<CertificateRecord | null>(null);
  const [editingCert, setEditingCert] = useState<CertificateRecord | null>(null);
  const [showAdminUnlockModal, setShowAdminUnlockModal] = useState(false);
  const [unlockPassword, setUnlockPassword] = useState('');
  const [unlockError, setUnlockError] = useState<string | null>(null);
  const [unlockBusy, setUnlockBusy] = useState(false);

  const loadAuthStatus = useCallback(async () => {
    setLoadingAuth(true);
    try {
      const status = await api.getAuthStatus();
      setAuthStatus(status);
      setSession(status.session);
    } catch {
      setAuthStatus(null);
      setSession(null);
    } finally {
      setLoadingAuth(false);
    }
  }, []);

  const loadRecentForMaker = useCallback(async () => {
    setLoadingRecent(true);
    try {
      const res = await api.getRecentCertificates();
      setRecentCertificates(res.certificates);
    } catch {
      setRecentCertificates([]);
    } finally {
      setLoadingRecent(false);
    }
  }, []);

  useEffect(() => {
    void loadAuthStatus();
    const onPopState = () => setRoute(parseRoute());
    window.addEventListener('popstate', onPopState);
    return () => window.removeEventListener('popstate', onPopState);
  }, [loadAuthStatus]);

  useEffect(() => {
    if (session?.role === 'maker') {
      void loadRecentForMaker();
    }
  }, [session, loadRecentForMaker]);

  const navigateToVerify = (certNumber = '', token = '') => {
    const qs = new URLSearchParams();
    if (certNumber) qs.set('certificateNumber', certNumber);
    if (token) qs.set('token', token);
    const nextUrl = qs.toString() ? `/verify?${qs.toString()}` : '/verify';
    window.history.pushState({}, '', nextUrl);
    setRoute({ isVerifyRoute: true, certNumber, token });
  };

  const navigateToPortal = () => {
    window.history.pushState({}, '', '/');
    setRoute({ isVerifyRoute: false, certNumber: '', token: '' });
  };

  const handleSessionExpired = useCallback(() => {
    setMemoryToken(null);
    setSession(null);
    setRecentCertificates([]);
    setSessionExpiredNotice('Your session expired or was invalidated. Please sign in again.');
    void loadAuthStatus();
  }, [loadAuthStatus]);

  const handleLogout = async () => {
    await api.logout();
    setSession(null);
    setRecentCertificates([]);
    setSessionExpiredNotice(null);
    await loadAuthStatus();
  };

  const handleMakerDelete = async (cert: CertificateRecord) => {
    await api.deleteCertificateMaker(cert.id);
    if (previewCert?.id === cert.id) {
      setPreviewCert(null);
    }
    if (editingCert?.id === cert.id) {
      setEditingCert(null);
    }
    setMakerNotice(
      `Certificate ${cert.certificateNumber} has been deleted from active records. Its certificate number remains permanently reserved.`
    );
    await loadRecentForMaker();
  };

  const handleQuickAdminUnlock = async (e: React.FormEvent) => {
    e.preventDefault();
    setUnlockError(null);
    setUnlockBusy(true);
    try {
      const adminSession = await api.unlockMainAdmin(unlockPassword);
      setSession(adminSession);
      setShowAdminUnlockModal(false);
      setUnlockPassword('');
    } catch (err) {
      setUnlockError(err instanceof ApiError ? err.message : 'Main Core Admin unlock failed.');
    } finally {
      setUnlockBusy(false);
    }
  };

  // Public QR Verification Route (No Login Required)
  if (route.isVerifyRoute) {
    return (
      <PublicVerifyView
        initialCertNumber={route.certNumber}
        initialToken={route.token}
        onBackToPortal={navigateToPortal}
      />
    );
  }

  if (loadingAuth || !authStatus) {
    return (
      <div className="min-h-screen bg-slate-50 flex items-center justify-center p-6">
        <div className="text-center">
          <div className="w-10 h-10 rounded-lg bg-[#0B1F3A] text-white font-display font-bold text-sm flex items-center justify-center mx-auto">
            PS
          </div>
          <p className="text-sm text-slate-600 mt-3">Connecting to Parivahan Scrappers Registry...</p>
        </div>
      </div>
    );
  }

  // Unauthenticated Front-Page Login & First-Run Setup
  if (!session) {
    return (
      <LoginView
        authStatus={authStatus}
        initialNotice={sessionExpiredNotice}
        onAuthenticated={(newSession) => {
          setSessionExpiredNotice(null);
          setSession(newSession);
        }}
        onBootstrapComplete={loadAuthStatus}
        onOpenPublicVerify={() => navigateToVerify()}
      />
    );
  }

  return (
    <div className="min-h-screen bg-slate-50 flex flex-col">
      {/* Authenticated Top Bar */}
      <header className="bg-[#0B1F3A] text-white border-b border-white/10 px-4 sm:px-6 py-3.5 sticky top-0 z-30">
        <div className="max-w-7xl mx-auto flex items-center justify-between gap-4">
          {/* Zone 1: Brand Wordmark */}
          <div className="flex items-center gap-3 whitespace-nowrap shrink-0">
            <div className="w-8 h-8 rounded-lg bg-[#059669] text-white flex items-center justify-center font-display font-bold text-xs">
              PS
            </div>
            <span className="font-display font-bold text-base sm:text-lg tracking-tight">
              Parivahan Scrappers
            </span>
          </div>

          {/* Zone 2: Active Role Context */}
          <div className="hidden md:flex items-center gap-5 text-xs text-slate-300">
            <span className="inline-flex items-center gap-1.5 font-semibold text-white whitespace-nowrap">
              {session.role === 'main_admin' ? (
                <ShieldCheck className="w-4 h-4 text-emerald-400" />
              ) : (
                <UserCheck className="w-4 h-4 text-emerald-400" />
              )}
              {session.role === 'main_admin' ? 'Main Core Admin' : 'Certificate Maker'}
            </span>
            <span className="text-slate-500">·</span>
            <span className="truncate max-w-[180px]">{session.username}</span>
            <span className="text-slate-500">·</span>
            <button
              type="button"
              onClick={() => navigateToVerify()}
              className="inline-flex items-center gap-1.5 hover:text-white transition-colors whitespace-nowrap cursor-pointer"
            >
              <QrCode className="w-3.5 h-3.5 text-emerald-400" />
              Public Verification
            </button>
          </div>

          {/* Zone 3: Primary Action / Sign Out */}
          <div className="flex items-center gap-2.5 shrink-0">
            {session.role === 'maker' && (
              <button
                type="button"
                onClick={() => {
                  setUnlockError(null);
                  setShowAdminUnlockModal(true);
                }}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white/10 hover:bg-white/15 border border-white/15 text-xs font-semibold text-white transition-colors whitespace-nowrap shrink-0 cursor-pointer"
              >
                <KeyRound className="w-3.5 h-3.5 text-emerald-300" />
                Main Core Admin
              </button>
            )}
            <button
              type="button"
              onClick={() => void handleLogout()}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white/10 hover:bg-red-600/80 text-xs font-semibold text-white transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              <LogOut className="w-3.5 h-3.5" />
              Sign Out
            </button>
          </div>
        </div>
      </header>

      {/* Main Role-Segregated Workspace */}
      <main className="flex-1">
        {session.role === 'maker' ? (
          <div className="max-w-6xl mx-auto px-4 sm:px-6 py-8 space-y-8">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div>
                <h1 className="font-display text-2xl font-bold text-[#0B1F3A]">
                  Certificate Maker Workspace
                </h1>
                <p className="text-sm text-slate-600 mt-0.5">
                  Role: Certificate Maker · Authorized for new certificate issuance and managing the
                  latest five records.
                </p>
              </div>
            </div>

            {makerNotice && (
              <div className="p-3.5 rounded-lg bg-emerald-50 border border-emerald-200 text-emerald-900 text-sm flex items-center justify-between gap-3">
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-[#059669] shrink-0" />
                  <span>{makerNotice}</span>
                </div>
                <button
                  type="button"
                  onClick={() => setMakerNotice(null)}
                  className="p-1 rounded-md text-emerald-700 hover:bg-emerald-100 cursor-pointer"
                  aria-label="Dismiss notice"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
            )}

            <CreateCertificateForm
              onCertificateCreated={() => {
                setMakerNotice(null);
                void loadRecentForMaker();
              }}
              onPreviewCertificate={(cert) => setPreviewCert(cert)}
              onSessionExpired={handleSessionExpired}
              pdfBranding={{
                customDomain: authStatus.publicDomain,
                authorizedSignatory: authStatus.authorizedSignatory,
                signatoryDesignation: authStatus.signatoryDesignation,
              }}
            />

            <RecentCertificatesPanel
              certificates={recentCertificates}
              loading={loadingRecent}
              onPreview={(cert) => setPreviewCert(cert)}
              onEdit={(cert) => setEditingCert(cert)}
              onDelete={handleMakerDelete}
              onOpenVerify={(cert) => navigateToVerify(cert.certificateNumber, cert.qrToken)}
              pdfBranding={{
                customDomain: authStatus.publicDomain,
                authorizedSignatory: authStatus.authorizedSignatory,
                signatoryDesignation: authStatus.signatoryDesignation,
              }}
            />
          </div>
        ) : (
          <AdminDashboard
            session={session}
            onSessionUpdated={(next) => setSession(next)}
            onPreviewCertificate={(cert) => setPreviewCert(cert)}
            onOpenPublicVerify={(cert) => navigateToVerify(cert.certificateNumber, cert.qrToken)}
            pdfBranding={{
              customDomain: authStatus.publicDomain,
              authorizedSignatory: authStatus.authorizedSignatory,
              signatoryDesignation: authStatus.signatoryDesignation,
            }}
          />
        )}
      </main>

      {/* Institutional Certificate Preview Modal */}
      <CertificatePreviewModal
        certificate={previewCert}
        onClose={() => setPreviewCert(null)}
        onOpenPublicVerify={(cert) => {
          setPreviewCert(null);
          navigateToVerify(cert.certificateNumber, cert.qrToken);
        }}
        pdfBranding={{
          customDomain: authStatus.publicDomain,
          authorizedSignatory: authStatus.authorizedSignatory,
          signatoryDesignation: authStatus.signatoryDesignation,
        }}
      />

      {/* Streamlined Maker Certificate Edit Modal */}
      <MakerEditCertificateModal
        key={editingCert?.id ?? 'closed'}
        certificate={editingCert}
        onClose={() => setEditingCert(null)}
        onSaved={(updated) => {
          setEditingCert(null);
          setPreviewCert(updated);
          setMakerNotice(
            `Certificate ${updated.certificateNumber} updated to v${updated.version}. SHA-256 integrity hash, QR verification token, preview, and PDF have been refreshed.`
          );
          void loadRecentForMaker();
        }}
      />

      {/* Separate Main Core Admin Unlock Modal (accessible from Maker view) */}
      {showAdminUnlockModal && (
        <div
          className="fixed inset-0 z-50 bg-slate-900/60 flex items-center justify-center p-4"
          role="dialog"
          aria-modal="true"
        >
          <div className="bg-white rounded-xl border border-slate-200 w-full max-w-md shadow-xl overflow-hidden">
            <div className="px-6 py-4 bg-[#0B1F3A] text-white flex items-center justify-between">
              <div className="flex items-center gap-2">
                <ShieldCheck className="w-5 h-5 text-emerald-400" />
                <h3 className="font-display font-bold text-base">Main Core Admin Unlock</h3>
              </div>
              <button
                type="button"
                onClick={() => setShowAdminUnlockModal(false)}
                className="p-1 rounded-md text-slate-300 hover:bg-white/10 cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <form onSubmit={handleQuickAdminUnlock} className="p-6 space-y-4">
              <p className="text-xs text-slate-600 leading-relaxed">
                Enter the separate Main Core Admin password to access the full certificate registry,
                statistics, protected edit/cancel/delete controls, audit logs, backups, and settings.
              </p>
              {unlockError && (
                <div className="p-3 rounded-lg bg-red-50 border border-red-200 text-red-800 text-xs flex items-start gap-2">
                  <AlertCircle className="w-4 h-4 shrink-0 text-red-600" />
                  <span>{unlockError}</span>
                </div>
              )}
              <div>
                <label className="block text-xs font-medium text-slate-700 mb-1.5">
                  Main Core Admin Password
                </label>
                <input
                  type="password"
                  required
                  autoFocus
                  value={unlockPassword}
                  onChange={(e) => setUnlockPassword(e.target.value)}
                  placeholder="Enter Main Core Admin password"
                  className="w-full px-3.5 py-2.5 rounded-lg border border-slate-300 text-sm focus:outline-none focus:ring-2 focus:ring-[#059669]"
                />
              </div>
              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowAdminUnlockModal(false)}
                  className="px-4 py-2 rounded-lg border border-slate-300 text-sm font-medium text-slate-700 cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={unlockBusy}
                  className="px-5 py-2 rounded-lg bg-[#059669] hover:bg-[#047857] text-white text-sm font-semibold cursor-pointer disabled:opacity-50"
                >
                  {unlockBusy ? 'Verifying...' : 'Unlock Console'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
