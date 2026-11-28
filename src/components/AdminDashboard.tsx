import React, { useCallback, useEffect, useState } from 'react';
import {
  Activity,
  AlertCircle,
  AlertTriangle,
  Archive,
  Ban,
  CheckCircle2,
  ClipboardList,
  Database,
  Download,
  Edit3,
  Eye,
  FilePlus2,
  FlaskConical,
  FolderSync,
  History,
  KeyRound,
  RefreshCw,
  RotateCcw,
  Search,
  Settings,
  ShieldAlert,
  ShieldCheck,
  X,
} from 'lucide-react';
import type {
  AuditLogEntry,
  BackupDryRunResult,
  BackupSnapshot,
  CertificateRecord,
  CertificateVersionDocument,
  CertificateVersionSnapshot,
  DashboardStats,
  DatabaseIntegrityReport,
  DriveSyncLog,
  OriginalCertificateSnapshot,
  SessionInfo,
  StagingRestoreVerificationResult,
  SystemErrorLog,
  SystemSettings,
} from '../shared/types';
import { api, ApiError } from '../lib/api';
import { formatChassisOrEngine } from '../shared/vehicleData';
import {
  downloadCertificatePdf,
  getCertificateBrand,
  type PdfBrandingOptions,
} from '../lib/pdfGenerator';
import { CreateCertificateForm } from './CreateCertificateForm';
import { ProtectedActionModal, type ProtectedActionMode } from './ProtectedActionModal';

interface AdminDashboardProps {
  session: SessionInfo;
  onSessionUpdated: (session: SessionInfo) => void;
  onPreviewCertificate: (cert: CertificateRecord) => void;
  onOpenPublicVerify: (cert: CertificateRecord) => void;
  initialScrapRouteAuthorized?: boolean;
  scrapRoutePinConfigured?: boolean;
  pdfBranding?: PdfBrandingOptions;
}

type AdminTab = 'registry' | 'issue' | 'integrity' | 'audit' | 'backups' | 'settings';

export const AdminDashboard: React.FC<AdminDashboardProps> = ({
  onSessionUpdated,
  onPreviewCertificate,
  initialScrapRouteAuthorized = false,
  scrapRoutePinConfigured = true,
  pdfBranding,
}) => {
  const [activeTab, setActiveTab] = useState<AdminTab>('registry');

  // Registry & Stats + Continuous Sync State
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [certificates, setCertificates] = useState<CertificateRecord[]>([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<'ALL' | 'ACTIVE' | 'CANCELLED' | 'SOFT_DELETED'>('ALL');
  const [loadingRegistry, setLoadingRegistry] = useState(true);
  const [hasLoadedRegistry, setHasLoadedRegistry] = useState(false);
  const [syncStatus, setSyncStatus] = useState<'idle' | 'syncing' | 'synced' | 'error'>('idle');
  const [lastSyncedAt, setLastSyncedAt] = useState<string | null>(null);
  const [syncError, setSyncError] = useState<string | null>(null);

  // Protected Action Modal
  const [actionCert, setActionCert] = useState<CertificateRecord | null>(null);
  const [actionMode, setActionMode] = useState<ProtectedActionMode | null>(null);

  // Immutable Version History Modal
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyError, setHistoryError] = useState<string | null>(null);
  const [historyPayload, setHistoryPayload] = useState<{
    certificate: CertificateRecord;
    originalRecord: OriginalCertificateSnapshot;
    versionHistory: CertificateVersionSnapshot[];
    appendOnlyVersions: CertificateVersionDocument[];
  } | null>(null);

  // Database Integrity & Backup Monitor
  const [integrityReport, setIntegrityReport] = useState<DatabaseIntegrityReport | null>(null);
  const [loadingIntegrity, setLoadingIntegrity] = useState(false);
  const [exportingRegistry, setExportingRegistry] = useState(false);

  // Audit Logs
  const [auditLogs, setAuditLogs] = useState<AuditLogEntry[]>([]);

  // Backups & Staging Verification
  const [backups, setBackups] = useState<BackupSnapshot[]>([]);
  const [dryRunResult, setDryRunResult] = useState<BackupDryRunResult | null>(null);
  const [stagingResult, setStagingResult] = useState<StagingRestoreVerificationResult | null>(null);
  const [restoreTargetId, setRestoreTargetId] = useState<string | null>(null);
  const [restoreConfirmPhrase, setRestoreConfirmPhrase] = useState('');
  const [restorePassword, setRestorePassword] = useState('');
  const [backupBusy, setBackupBusy] = useState(false);

  // Settings, Security & Health
  const [settings, setSettings] = useState<SystemSettings | null>(null);
  const [envManagedCreds, setEnvManagedCreds] = useState(false);
  const [staleMakerEnvIgnored, setStaleMakerEnvIgnored] = useState(false);
  const [activeMakerUsername, setActiveMakerUsername] = useState('');
  const [driveEnvConfigured, setDriveEnvConfigured] = useState(false);
  const [healthInfo, setHealthInfo] = useState<{
    status: string;
    storageMode: 'firestore' | 'staging_memory' | 'firestore_unconfigured';
    firestoreConnected: boolean;
    storageLatencyMs: number;
    storageMessage: string;
    firestoreProjectId: string | null;
    firestoreDatabaseId: string | null;
    nodeVersion: string;
    uptimeSeconds: number;
    reservedCertNumbers: number;
    reservedRegNumbers: number;
    driveConfigured: boolean;
    recentErrors: SystemErrorLog[];
    driveLogs: DriveSyncLog[];
  } | null>(null);

  // Password Rotation
  const [currentMainPassword, setCurrentMainPassword] = useState('');
  const [newMakerPassword, setNewMakerPassword] = useState('');
  const [confirmMakerPassword, setConfirmMakerPassword] = useState('');
  const [newMainAdminPassword, setNewMainAdminPassword] = useState('');
  const [newProtectedPassword, setNewProtectedPassword] = useState('');

  // Feedback
  const [banner, setBanner] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const loadRegistryAndStats = useCallback(
    async (opts?: { silent?: boolean }) => {
      if (!opts?.silent) {
        setLoadingRegistry(true);
      }
      setSyncStatus('syncing');
      try {
        const [statsRes, certsRes] = await Promise.all([
          api.getAdminStats(),
          api.getAdminCertificates({ search: searchQuery, status: statusFilter }),
        ]);
        setStats(statsRes);
        setCertificates(certsRes.certificates);
        setHasLoadedRegistry(true);
        setSyncStatus('synced');
        setLastSyncedAt(new Date().toISOString());
        setSyncError(null);
      } catch (err) {
        // NEVER wipe cached certificates or stats to zero on sync failure
        setSyncStatus('error');
        const detail = err instanceof ApiError ? ` (${err.message})` : '';
        setSyncError(`SYNC ERROR — EXISTING DATABASE RECORDS HAVE BEEN PRESERVED.${detail}`);
      } finally {
        if (!opts?.silent) {
          setLoadingRegistry(false);
        }
      }
    },
    [searchQuery, statusFilter]
  );

  const loadIntegrityMonitor = useCallback(async () => {
    setLoadingIntegrity(true);
    try {
      const res = await api.getIntegrityMonitor();
      setIntegrityReport(res.report);
    } catch (err) {
      setBanner({
        type: 'error',
        text: err instanceof ApiError ? err.message : 'Unable to run read-only integrity audit.',
      });
    } finally {
      setLoadingIntegrity(false);
    }
  }, []);

  const loadAuditLogs = useCallback(async () => {
    try {
      const res = await api.getAuditLogs();
      setAuditLogs(res.logs);
    } catch {
      // preserve previously loaded logs
    }
  }, []);

  const loadBackups = useCallback(async () => {
    try {
      const res = await api.getBackups();
      setBackups(res.backups);
    } catch {
      // preserve previously loaded backups
    }
  }, []);

  const loadSettingsAndHealth = useCallback(async () => {
    try {
      const [settingsRes, healthRes] = await Promise.all([
        api.getSettings(),
        api.getAdminHealth(),
      ]);
      setSettings(settingsRes.settings);
      setEnvManagedCreds(settingsRes.envManagedCredentials);
      setStaleMakerEnvIgnored(settingsRes.staleMakerEnvIgnored);
      setActiveMakerUsername(settingsRes.makerUsername);
      setDriveEnvConfigured(settingsRes.driveEnvConfigured);
      setHealthInfo(healthRes);
    } catch {
      // preserve previously loaded settings/health
    }
  }, []);

  useEffect(() => {
    void loadRegistryAndStats();
  }, [loadRegistryAndStats]);

  // Continuous background database sync (30s interval when visible + window focus)
  useEffect(() => {
    const interval = window.setInterval(() => {
      if (document.visibilityState === 'visible') {
        void loadRegistryAndStats({ silent: true });
      }
    }, 30_000);

    const onFocus = () => {
      void loadRegistryAndStats({ silent: true });
    };
    window.addEventListener('focus', onFocus);

    return () => {
      window.clearInterval(interval);
      window.removeEventListener('focus', onFocus);
    };
  }, [loadRegistryAndStats]);

  useEffect(() => {
    if (activeTab === 'integrity') void loadIntegrityMonitor();
    if (activeTab === 'audit') void loadAuditLogs();
    if (activeTab === 'backups') void loadBackups();
    if (activeTab === 'settings') void loadSettingsAndHealth();
  }, [activeTab, loadIntegrityMonitor, loadAuditLogs, loadBackups, loadSettingsAndHealth]);

  const handleOpenHistory = async (cert: CertificateRecord) => {
    setHistoryError(null);
    setHistoryLoading(true);
    try {
      const data = await api.getCertificateHistory(cert.id);
      setHistoryPayload(data);
    } catch (err) {
      setHistoryError(
        err instanceof ApiError ? err.message : 'Unable to load certificate version history.'
      );
      setBanner({
        type: 'error',
        text: err instanceof ApiError ? err.message : 'Unable to load certificate version history.',
      });
    } finally {
      setHistoryLoading(false);
    }
  };

  const handleExportRegistry = async () => {
    setBanner(null);
    setExportingRegistry(true);
    try {
      await api.exportFullRegistryJson();
      setBanner({
        type: 'success',
        text: 'Owner-authorized full registry JSON export downloaded and recorded in audit logs.',
      });
    } catch (err) {
      setBanner({
        type: 'error',
        text: err instanceof ApiError ? err.message : 'Registry export failed.',
      });
    } finally {
      setExportingRegistry(false);
    }
  };

  const handleStagingVerify = async (id: string) => {
    setBanner(null);
    setBackupBusy(true);
    try {
      const res = await api.verifyBackupInStaging(id);
      setStagingResult(res.stagingResult);
    } catch (err) {
      setBanner({
        type: 'error',
        text: err instanceof ApiError ? err.message : 'Isolated staging verification failed.',
      });
    } finally {
      setBackupBusy(false);
    }
  };

  const handleCreateBackup = async () => {
    setBanner(null);
    setBackupBusy(true);
    try {
      const res = await api.createBackup();
      setBanner({
        type: 'success',
        text: `Verified backup ${res.backup.id} created (${res.backup.certificateCount} certificates, SHA-256: ${res.backup.sha256Checksum.slice(0, 16)}...).`,
      });
      await Promise.all([loadBackups(), loadRegistryAndStats()]);
    } catch (err) {
      setBanner({
        type: 'error',
        text: err instanceof ApiError ? err.message : 'Backup creation failed.',
      });
    } finally {
      setBackupBusy(false);
    }
  };

  const handleDryRun = async (id: string) => {
    setBanner(null);
    setBackupBusy(true);
    try {
      const res = await api.dryRunBackup(id);
      setDryRunResult(res.dryRun);
      setRestoreTargetId(id);
    } catch (err) {
      setBanner({
        type: 'error',
        text: err instanceof ApiError ? err.message : 'Dry-run verification failed.',
      });
    } finally {
      setBackupBusy(false);
    }
  };

  const handleExecuteRestore = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!restoreTargetId) return;
    setBanner(null);
    setBackupBusy(true);
    try {
      const res = await api.restoreBackup(restoreTargetId, {
        protectedPassword: restorePassword,
        confirmPhrase: restoreConfirmPhrase,
      });
      setBanner({
        type: 'success',
        text: `Restore complete (${res.restoredCount} certificate(s) restored). Automatic safety snapshot saved: ${res.safetyBackupId}.`,
      });
      setDryRunResult(null);
      setRestoreTargetId(null);
      setRestoreConfirmPhrase('');
      setRestorePassword('');
      await Promise.all([loadBackups(), loadRegistryAndStats()]);
    } catch (err) {
      setBanner({
        type: 'error',
        text: err instanceof ApiError ? err.message : 'Restore failed.',
      });
    } finally {
      setBackupBusy(false);
    }
  };

  const handleSaveSettings = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!settings) return;
    setBanner(null);
    try {
      const res = await api.updateSettings(settings);
      setSettings(res.settings);
      setBanner({ type: 'success', text: 'Facility and backup settings saved.' });
    } catch (err) {
      setBanner({
        type: 'error',
        text: err instanceof ApiError ? err.message : 'Failed to update settings.',
      });
    }
  };

  const handleRotatePasswords = async (e: React.FormEvent) => {
    e.preventDefault();
    setBanner(null);
    if (newMakerPassword && newMakerPassword !== confirmMakerPassword) {
      setBanner({ type: 'error', text: 'New Maker password and confirmation do not match.' });
      return;
    }
    if (!newMakerPassword && !newMainAdminPassword && !newProtectedPassword) {
      setBanner({ type: 'error', text: 'Enter at least one new password to rotate.' });
      return;
    }
    try {
      const makerOnly =
        Boolean(newMakerPassword) && !newMainAdminPassword && !newProtectedPassword;
      const res = makerOnly
        ? await api.rotateMakerPassword({
            currentMainPassword,
            newMakerPassword,
          })
        : await api.rotatePasswords({
            currentMainPassword,
            newMakerPassword: newMakerPassword || undefined,
            newMainAdminPassword: newMainAdminPassword || undefined,
            newProtectedPassword: newProtectedPassword || undefined,
          });
      onSessionUpdated(res.session);
      setCurrentMainPassword('');
      setNewMakerPassword('');
      setConfirmMakerPassword('');
      setNewMainAdminPassword('');
      setNewProtectedPassword('');
      setBanner({ type: 'success', text: res.message });
    } catch (err) {
      setBanner({
        type: 'error',
        text: err instanceof ApiError ? err.message : 'Password rotation failed.',
      });
    }
  };

  const navItems: Array<{ id: AdminTab; label: string; icon: React.ReactNode }> = [
    { id: 'registry', label: 'Full Registry', icon: <ShieldCheck className="w-4 h-4" /> },
    { id: 'issue', label: 'Make Certificate', icon: <FilePlus2 className="w-4 h-4" /> },
    { id: 'integrity', label: 'Integrity & Backup', icon: <ShieldAlert className="w-4 h-4" /> },
    { id: 'audit', label: 'Audit Logs', icon: <ClipboardList className="w-4 h-4" /> },
    { id: 'backups', label: 'Backups & Restore', icon: <Database className="w-4 h-4" /> },
    { id: 'settings', label: 'Settings & Health', icon: <Settings className="w-4 h-4" /> },
  ];

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 py-6">
      {/* Sub-Navigation Bar */}
      <div className="flex flex-wrap items-center justify-between gap-4 mb-5">
        <div className="flex items-center gap-1 p-1 bg-white border border-slate-200 rounded-lg overflow-x-auto">
          {navItems.map((item) => (
            <button
              key={item.id}
              type="button"
              onClick={() => {
                setActiveTab(item.id);
                setBanner(null);
              }}
              className={`inline-flex items-center gap-2 px-3.5 py-2 rounded-md text-xs sm:text-sm font-semibold transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                activeTab === item.id
                  ? 'bg-[#0B1F3A] text-white'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
              }`}
            >
              {item.icon}
              {item.label}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-3 shrink-0">
          <span className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-600">
            {syncStatus === 'error' ? (
              <AlertTriangle className="w-3.5 h-3.5 text-red-600" />
            ) : syncStatus === 'syncing' ? (
              <RefreshCw className="w-3.5 h-3.5 text-[#0B1F3A] animate-spin" />
            ) : (
              <CheckCircle2 className="w-3.5 h-3.5 text-[#059669]" />
            )}
            {syncStatus === 'error'
              ? 'Sync Error'
              : syncStatus === 'syncing'
                ? 'Syncing...'
                : lastSyncedAt
                  ? `Synced · ${new Date(lastSyncedAt).toLocaleTimeString()}`
                  : 'Connected'}
          </span>
          <button
            type="button"
            onClick={() => {
              void loadRegistryAndStats();
              if (activeTab === 'integrity') void loadIntegrityMonitor();
              if (activeTab === 'audit') void loadAuditLogs();
              if (activeTab === 'backups') void loadBackups();
              if (activeTab === 'settings') void loadSettingsAndHealth();
            }}
            className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg border border-slate-300 bg-white hover:bg-slate-50 text-xs font-semibold text-slate-700 cursor-pointer whitespace-nowrap"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh Data
          </button>
        </div>
      </div>

      {syncError && (
        <div
          role="alert"
          className="mb-5 p-4 rounded-xl bg-red-50 border border-red-300 text-red-950 text-sm flex flex-col sm:flex-row sm:items-center justify-between gap-3"
        >
          <div className="flex items-start gap-2.5 font-semibold">
            <AlertTriangle className="w-5 h-5 shrink-0 text-red-600 mt-0.5" />
            <span>{syncError}</span>
          </div>
          <button
            type="button"
            onClick={() => void loadRegistryAndStats()}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-white border border-red-300 hover:bg-red-100 text-xs font-semibold text-red-800 whitespace-nowrap shrink-0 cursor-pointer"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Retry Database Sync
          </button>
        </div>
      )}

      {banner && (
        <div
          role="alert"
          className={`mb-6 p-4 rounded-lg border text-sm flex items-start gap-2.5 ${
            banner.type === 'success'
              ? 'bg-emerald-50 border-emerald-200 text-emerald-950'
              : 'bg-red-50 border-red-200 text-red-900'
          }`}
        >
          {banner.type === 'success' ? (
            <CheckCircle2 className="w-4 h-4 shrink-0 mt-0.5 text-[#059669]" />
          ) : (
            <AlertCircle className="w-4 h-4 shrink-0 mt-0.5 text-red-600" />
          )}
          <span>{banner.text}</span>
        </div>
      )}

      {/* ==================================================================== */}
      {/* TAB 1: REGISTRY & STATISTICS */}
      {/* ==================================================================== */}
      {activeTab === 'registry' && (
        <div className="space-y-6">
          {/* 4-Column KPI Summary Strip */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="bg-white border border-slate-200 rounded-xl p-5">
              <p className="text-xs font-medium text-slate-500">Total Certificates</p>
              <p className="font-mono text-2xl font-bold text-[#0B1F3A] mt-1 tabular-nums">
                {stats?.totalCertificates ?? 0}
              </p>
              <p className="text-xs text-slate-500 mt-1 tabular-nums">
                {stats?.issuedToday ?? 0} today · {stats?.issuedThisMonth ?? 0} this month
              </p>
            </div>

            <div className="bg-white border border-slate-200 rounded-xl p-5">
              <p className="text-xs font-medium text-slate-500">Active Verified</p>
              <p className="font-mono text-2xl font-bold text-[#059669] mt-1 tabular-nums">
                {stats?.activeCertificates ?? 0}
              </p>
              <p className="text-xs text-slate-500 mt-1">Valid for public QR lookup</p>
            </div>

            <div className="bg-white border border-slate-200 rounded-xl p-5">
              <p className="text-xs font-medium text-slate-500">Cancelled / Archived</p>
              <p className="font-mono text-2xl font-bold text-slate-900 mt-1 tabular-nums">
                {stats?.cancelledCertificates ?? 0}{' '}
                <span className="text-slate-300 font-normal">/</span>{' '}
                {stats?.softDeletedCertificates ?? 0}
              </p>
              <p className="text-xs text-slate-500 mt-1">Archived records remain restorable</p>
            </div>

            <div className="bg-white border border-slate-200 rounded-xl p-5">
              <p className="text-xs font-medium text-slate-500">Reserved Number Pools</p>
              <p className="font-mono text-2xl font-bold text-[#0B1F3A] mt-1 tabular-nums">
                {stats?.reservedCertNumbers ?? 0}
              </p>
              <p className="text-xs text-slate-500 mt-1 tabular-nums">
                {stats?.totalBackups ?? 0} verified backup snapshot(s)
              </p>
            </div>
          </div>

          {/* Search & Filter Toolbar */}
          <div className="bg-white border border-slate-200 rounded-xl overflow-hidden">
            <div className="p-4 sm:p-5 border-b border-slate-200 flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div className="relative flex-1 max-w-md">
                <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Search cert no., reg no., owner, vehicle, chassis..."
                  className="w-full pl-10 pr-4 py-2 rounded-lg border border-slate-300 text-sm focus:outline-none focus:ring-2 focus:ring-[#059669]"
                />
              </div>

              <div className="flex items-center gap-1 p-1 bg-slate-100 rounded-lg overflow-x-auto">
                {(['ALL', 'ACTIVE', 'CANCELLED', 'SOFT_DELETED'] as const).map((st) => (
                  <button
                    key={st}
                    type="button"
                    onClick={() => setStatusFilter(st)}
                    className={`px-3 py-1.5 rounded-md text-xs font-semibold transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                      statusFilter === st
                        ? 'bg-white text-[#0B1F3A] shadow-sm'
                        : 'text-slate-600 hover:text-slate-900'
                    }`}
                  >
                    {st === 'ALL'
                      ? 'All'
                      : st === 'SOFT_DELETED'
                        ? 'Archived'
                        : st.charAt(0) + st.slice(1).toLowerCase()}
                  </button>
                ))}
              </div>
            </div>

            {loadingRegistry && !hasLoadedRegistry ? (
              <div className="p-10 text-center text-sm text-slate-500">
                Synchronizing full certificate registry from Firestore...
              </div>
            ) : certificates.length === 0 && syncError ? (
              <div className="p-12 text-center">
                <p className="font-semibold text-sm text-red-800">
                  SYNC ERROR — EXISTING DATABASE RECORDS HAVE BEEN PRESERVED.
                </p>
                <p className="text-xs text-slate-600 mt-1 max-w-md mx-auto">
                  The registry could not be refreshed from Firestore right now. No database records
                  have been altered or removed. Click Retry Database Sync above to reconnect.
                </p>
              </div>
            ) : certificates.length === 0 && hasLoadedRegistry ? (
              <div className="p-12 text-center">
                <p className="font-semibold text-sm text-slate-900">
                  {searchQuery || statusFilter !== 'ALL'
                    ? 'No certificates match the current search or filter.'
                    : 'No Certificates Found in This Registry Yet'}
                </p>
                <p className="text-xs text-slate-500 mt-1">
                  {searchQuery || statusFilter !== 'ALL'
                    ? 'Try clearing the search query or switching status filter.'
                    : 'Issue a new certificate to begin recording permanently in Firestore.'}
                </p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse text-sm">
                  <thead>
                    <tr className="border-b border-slate-200 bg-slate-50 text-xs font-semibold text-slate-600">
                      <th className="py-3 px-5">Certificate & Reg. No.</th>
                      <th className="py-3 px-4">Owner</th>
                      <th className="py-3 px-4">Vehicle & Chassis</th>
                      <th className="py-3 px-4">Date & Ver.</th>
                      <th className="py-3 px-4">Status</th>
                      <th className="py-3 px-5 text-right">Protected Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-200">
                    {certificates.map((cert) => {
                      const isSr = getCertificateBrand(cert) === 'scrap_route';
                      return (
                      <tr key={cert.id} className="hover:bg-slate-50/70">
                        <td className="py-3.5 px-5">
                          <div className="flex items-center gap-2">
                            <span className="font-mono font-semibold text-[#0B1F3A] tabular-nums">
                              {cert.certificateNumber}
                            </span>
                            <span
                              className={`text-[10px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded border ${
                                isSr
                                  ? 'bg-emerald-50 text-emerald-900 border-emerald-200'
                                  : 'bg-blue-50 text-[#0B1F3A] border-blue-200'
                              }`}
                            >
                              {isSr ? 'Scrap Route' : 'Parivahan'}
                            </span>
                          </div>
                          <div className="font-mono text-xs text-slate-500 tabular-nums">
                            {cert.scrappingRegNumber}
                          </div>
                        </td>
                        <td className="py-3.5 px-4">
                          <div className="font-medium text-slate-900">{cert.ownerName}</div>
                          {cert.ownerAddress && (
                            <div className="text-xs text-slate-500 truncate max-w-[220px]">
                              {cert.ownerAddress}
                            </div>
                          )}
                        </td>
                        <td className="py-3.5 px-4">
                          <div className="font-mono font-semibold text-slate-900">
                            {cert.vehicleRegNumber}
                          </div>
                          <div className="text-xs text-slate-500">
                            {cert.make} {cert.model} ·{' '}
                            <span className="font-mono">
                              {formatChassisOrEngine(cert.chassisNumber, cert.unhideChassisEngine)}
                            </span>
                          </div>
                        </td>
                        <td className="py-3.5 px-4 font-mono text-xs text-slate-700 tabular-nums">
                          <div>{cert.issueDate}</div>
                          <div className="text-slate-500">v{cert.version}</div>
                        </td>
                        <td className="py-3.5 px-4">
                          <span
                            className={`text-xs font-semibold ${
                              cert.status === 'ACTIVE'
                                ? 'text-[#059669]'
                                : cert.status === 'CANCELLED'
                                  ? 'text-amber-700'
                                  : 'text-slate-600'
                            }`}
                          >
                            {cert.status === 'SOFT_DELETED' ? 'ARCHIVED' : cert.status}
                          </span>
                        </td>
                        <td className="py-3.5 px-5 text-right">
                          <div className="inline-flex items-center gap-1.5 flex-wrap justify-end">
                            <button
                              type="button"
                              onClick={() => onPreviewCertificate(cert)}
                              title="Preview Certificate & QR"
                              className="p-1.5 rounded-md border border-slate-300 bg-white hover:bg-slate-100 text-slate-700 cursor-pointer"
                            >
                              <Eye className="w-3.5 h-3.5" />
                            </button>
                            <button
                              type="button"
                              onClick={() => void downloadCertificatePdf(cert, pdfBranding)}
                              title="Download Official PDF"
                              className="p-1.5 rounded-md border border-slate-300 bg-white hover:bg-slate-100 text-[#0B1F3A] cursor-pointer"
                            >
                              <Download className="w-3.5 h-3.5" />
                            </button>
                            <button
                              type="button"
                              onClick={() => void handleOpenHistory(cert)}
                              title="View Immutable Version History"
                              className="p-1.5 rounded-md border border-slate-300 bg-white hover:bg-slate-100 text-slate-700 cursor-pointer"
                            >
                              <History className="w-3.5 h-3.5" />
                            </button>
                            <button
                              type="button"
                              onClick={() => {
                                setActionCert(cert);
                                setActionMode('edit');
                              }}
                              title="Protected Edit"
                              className="p-1.5 rounded-md border border-slate-300 bg-white hover:bg-slate-100 text-slate-700 cursor-pointer"
                            >
                              <Edit3 className="w-3.5 h-3.5" />
                            </button>
                            {cert.status === 'ACTIVE' && (
                              <button
                                type="button"
                                onClick={() => {
                                  setActionCert(cert);
                                  setActionMode('cancel');
                                }}
                                title="Protected Cancel"
                                className="p-1.5 rounded-md border border-amber-300 bg-amber-50 hover:bg-amber-100 text-amber-800 cursor-pointer"
                              >
                                <Ban className="w-3.5 h-3.5" />
                              </button>
                            )}
                            {cert.status !== 'SOFT_DELETED' ? (
                              <button
                                type="button"
                                onClick={() => {
                                  setActionCert(cert);
                                  setActionMode('soft_delete');
                                }}
                                title="Archive Certificate (Reversible)"
                                className="p-1.5 rounded-md border border-amber-200 bg-amber-50 hover:bg-amber-100 text-amber-800 cursor-pointer"
                              >
                                <Archive className="w-3.5 h-3.5" />
                              </button>
                            ) : (
                              <>
                                <button
                                  type="button"
                                  onClick={() => {
                                    setActionCert(cert);
                                    setActionMode('restore');
                                  }}
                                  title="Restore Archived Certificate"
                                  className="p-1.5 rounded-md border border-emerald-300 bg-emerald-50 hover:bg-emerald-100 text-emerald-800 cursor-pointer"
                                >
                                  <RotateCcw className="w-3.5 h-3.5" />
                                </button>
                                <button
                                  type="button"
                                  onClick={() => {
                                    setActionCert(cert);
                                    setActionMode('permanent_delete');
                                  }}
                                  title="Owner-Authorized Permanent Delete"
                                  className="px-2 py-1 rounded-md bg-red-700 hover:bg-red-800 text-[11px] font-semibold text-white cursor-pointer"
                                >
                                  Purge
                                </button>
                              </>
                            )}
                          </div>
                        </td>
                      </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ==================================================================== */}
      {/* TAB 2: ISSUE CERTIFICATE */}
      {/* ==================================================================== */}
      {activeTab === 'issue' && (
        <CreateCertificateForm
          onCertificateCreated={() => {
            void loadRegistryAndStats();
          }}
          onPreviewCertificate={onPreviewCertificate}
          initialScrapRouteAuthorized={initialScrapRouteAuthorized}
          scrapRoutePinConfigured={scrapRoutePinConfigured}
          pdfBranding={pdfBranding}
        />
      )}

      {/* ==================================================================== */}
      {/* TAB 2B: DATABASE INTEGRITY & BACKUP MONITOR (READ-ONLY) */}
      {/* ==================================================================== */}
      {activeTab === 'integrity' && (
        <div className="space-y-6">
          <div className="bg-white border border-slate-200 rounded-xl p-6 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
            <div>
              <div className="flex items-center gap-2">
                <ShieldCheck className="w-5 h-5 text-[#059669]" />
                <h2 className="font-display font-bold text-base text-[#0B1F3A] tracking-tight">
                  DATABASE INTEGRITY &amp; BACKUP MONITOR
                </h2>
              </div>
              <p className="text-xs text-slate-600 mt-1 max-w-2xl leading-relaxed">
                Strictly read-only diagnostic monitor for Main Core Admin. Audits SHA-256 canonical
                hashes, brand prefixes, reserved number pools, version histories, and backup health
                without automatically modifying, repairing, or deleting any database record.
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-2.5 shrink-0">
              <button
                type="button"
                onClick={() => void handleExportRegistry()}
                disabled={exportingRegistry}
                className="inline-flex items-center gap-2 px-4 py-2 rounded-lg border border-slate-300 bg-white hover:bg-slate-50 text-xs sm:text-sm font-semibold text-[#0B1F3A] disabled:opacity-50 cursor-pointer"
              >
                <Download className="w-4 h-4" />
                {exportingRegistry ? 'Exporting JSON...' : 'Export Full Registry JSON'}
              </button>
              <button
                type="button"
                onClick={() => void loadIntegrityMonitor()}
                disabled={loadingIntegrity}
                className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-[#0B1F3A] hover:bg-[#132f57] text-white text-xs sm:text-sm font-semibold disabled:opacity-50 cursor-pointer"
              >
                <RefreshCw className={`w-4 h-4 ${loadingIntegrity ? 'animate-spin' : ''}`} />
                {loadingIntegrity ? 'Auditing...' : 'Run Read-Only Integrity Audit'}
              </button>
            </div>
          </div>

          {integrityReport ? (
            <>
              {/* Backup Failure Alert Banner */}
              {integrityReport.backupHealth.recentBackupFailures > 0 && (
                <div
                  role="alert"
                  className="p-4 rounded-xl bg-red-50 border border-red-300 text-red-950 text-xs sm:text-sm space-y-1"
                >
                  <p className="font-bold flex items-center gap-2 text-red-800">
                    <AlertTriangle className="w-4 h-4 shrink-0" />
                    Backup Failure Alert ({integrityReport.backupHealth.recentBackupFailures} failure
                    event(s) logged)
                  </p>
                  <p className="text-red-900">
                    Last failure:{' '}
                    {integrityReport.backupHealth.lastBackupFailureAt
                      ? new Date(integrityReport.backupHealth.lastBackupFailureAt).toLocaleString()
                      : 'Recorded'}{' '}
                    — {integrityReport.backupHealth.lastBackupFailureMessage || 'Check server logs.'}{' '}
                    Previous verified backups were preserved untouched.
                  </p>
                </div>
              )}

              {/* 11 Required Metrics Grid */}
              <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-4">
                <div className="bg-white border border-slate-200 rounded-xl p-4">
                  <p className="text-xs text-slate-500">Total Parivahan Certificates</p>
                  <p className="font-mono text-2xl font-bold text-[#0B1F3A] mt-1 tabular-nums">
                    {integrityReport.counts.parivahanCertificates}
                  </p>
                </div>
                <div className="bg-white border border-slate-200 rounded-xl p-4">
                  <p className="text-xs text-slate-500">Total Scrap Route Certificates</p>
                  <p className="font-mono text-2xl font-bold text-[#065F46] mt-1 tabular-nums">
                    {integrityReport.counts.scrapRouteCertificates}
                  </p>
                </div>
                <div className="bg-white border border-slate-200 rounded-xl p-4">
                  <p className="text-xs text-slate-500">Total Active Certificates</p>
                  <p className="font-mono text-2xl font-bold text-[#059669] mt-1 tabular-nums">
                    {integrityReport.counts.activeCertificates}
                  </p>
                </div>
                <div className="bg-white border border-slate-200 rounded-xl p-4">
                  <p className="text-xs text-slate-500">Total Archived Certificates</p>
                  <p className="font-mono text-2xl font-bold text-slate-800 mt-1 tabular-nums">
                    {integrityReport.counts.archivedCertificates}
                  </p>
                </div>
                <div className="bg-white border border-slate-200 rounded-xl p-4">
                  <p className="text-xs text-slate-500">Total Reserved Certificate Numbers</p>
                  <p className="font-mono text-2xl font-bold text-[#0B1F3A] mt-1 tabular-nums">
                    {integrityReport.counts.reservedCertNumbers}
                  </p>
                </div>
                <div className="bg-white border border-slate-200 rounded-xl p-4">
                  <p className="text-xs text-slate-500">Total Failed Issuance Attempts</p>
                  <p className="font-mono text-2xl font-bold text-amber-700 mt-1 tabular-nums">
                    {integrityReport.counts.failedIssuanceAttempts}
                  </p>
                </div>
                <div className="bg-white border border-slate-200 rounded-xl p-4">
                  <p className="text-xs text-slate-500">Total Modified Certificates</p>
                  <p className="font-mono text-2xl font-bold text-[#0B1F3A] mt-1 tabular-nums">
                    {integrityReport.counts.modifiedCertificates}
                  </p>
                </div>
                <div className="bg-white border border-slate-200 rounded-xl p-4">
                  <p className="text-xs text-slate-500">Total Integrity Mismatches</p>
                  <p
                    className={`font-mono text-2xl font-bold mt-1 tabular-nums ${
                      integrityReport.counts.integrityMismatches === 0
                        ? 'text-[#059669]'
                        : 'text-red-700'
                    }`}
                  >
                    {integrityReport.counts.integrityMismatches}
                  </p>
                </div>
                <div className="bg-white border border-slate-200 rounded-xl p-4">
                  <p className="text-xs text-slate-500">Last Successful Backup</p>
                  <p className="font-mono text-xs font-semibold text-[#0B1F3A] mt-1.5">
                    {integrityReport.backupHealth.lastSuccessfulBackupAt
                      ? new Date(integrityReport.backupHealth.lastSuccessfulBackupAt).toLocaleString()
                      : 'None recorded yet'}
                  </p>
                  <p className="text-[11px] text-slate-500 mt-0.5">
                    {integrityReport.backupHealth.totalBackups} verified snapshot(s)
                  </p>
                </div>
                <div className="bg-white border border-slate-200 rounded-xl p-4">
                  <p className="text-xs text-slate-500">Last Successful Synchronization</p>
                  <p className="font-mono text-xs font-semibold text-[#0B1F3A] mt-1.5">
                    {lastSyncedAt ? new Date(lastSyncedAt).toLocaleString() : 'Pending'}
                  </p>
                  <p className="text-[11px] text-slate-500 mt-0.5">
                    Status: {syncStatus.toUpperCase()}
                  </p>
                </div>
                <div className="bg-white border border-slate-200 rounded-xl p-4 md:col-span-2">
                  <p className="text-xs text-slate-500">Last Integrity Audit</p>
                  <p className="font-mono text-xs font-semibold text-[#0B1F3A] mt-1.5">
                    {new Date(integrityReport.lastIntegrityAuditAt).toLocaleString()}
                  </p>
                  <p className="text-[11px] mt-0.5 font-semibold text-slate-600">
                    Overall Status:{' '}
                    <span className={integrityReport.healthy ? 'text-[#059669]' : 'text-red-700'}>
                      {integrityReport.healthy
                        ? 'HEALTHY — ZERO CRITICAL DISCREPANCIES'
                        : 'ATTENTION REQUIRED — DISCREPANCIES DETECTED'}
                    </span>
                  </p>
                </div>
              </div>

              {/* Discrepancy Report Table (Read-Only) */}
              <div className="bg-white border border-slate-200 rounded-xl overflow-hidden">
                <div className="px-6 py-4 border-b border-slate-200 flex items-center justify-between gap-2">
                  <div>
                    <h3 className="font-display font-bold text-sm text-[#0B1F3A]">
                      Read-Only Discrepancy Report
                    </h3>
                    <p className="text-xs text-slate-500 mt-0.5">
                      Findings are reported for owner review only. This audit never modifies,
                      auto-repairs, or deletes any certificate record.
                    </p>
                  </div>
                  <span className="font-mono text-xs text-slate-600 tabular-nums">
                    {integrityReport.discrepancies.length} finding(s)
                  </span>
                </div>
                {integrityReport.discrepancies.length === 0 ? (
                  <div className="p-8 text-center text-sm text-emerald-800 bg-emerald-50/40">
                    All certificate hashes, brand prefixes, reserved numbers, version histories,
                    and backup checks passed with zero discrepancies.
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left border-collapse text-xs">
                      <thead>
                        <tr className="border-b border-slate-200 bg-slate-50 font-semibold text-slate-600">
                          <th className="py-3 px-5">Severity</th>
                          <th className="py-3 px-4">Code</th>
                          <th className="py-3 px-4">Certificate</th>
                          <th className="py-3 px-5">Finding &amp; Details</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-200">
                        {integrityReport.discrepancies.map((d, idx) => (
                          <tr key={`${d.code}_${d.certificateId ?? idx}`}>
                            <td className="py-3 px-5">
                              <span
                                className={`font-bold px-2 py-0.5 rounded text-[11px] ${
                                  d.severity === 'CRITICAL'
                                    ? 'bg-red-100 text-red-800'
                                    : 'bg-amber-100 text-amber-800'
                                }`}
                              >
                                {d.severity}
                              </span>
                            </td>
                            <td className="py-3 px-4 font-mono text-slate-800">{d.code}</td>
                            <td className="py-3 px-4 font-mono text-[#0B1F3A]">
                              {d.certificateNumber || '-'}
                            </td>
                            <td className="py-3 px-5 text-slate-700">
                              <div>{d.message}</div>
                              {d.details && (
                                <div className="text-[11px] text-slate-500 mt-0.5">{d.details}</div>
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>

              {/* Transparent Firebase Plan & Backup Strategy Card */}
              <div className="bg-slate-50 border border-slate-200 rounded-xl p-5 text-xs text-slate-700 space-y-2">
                <p className="font-semibold text-[#0B1F3A]">
                  Firebase Plan Transparency &amp; Active Protection Strategy
                </p>
                <p>{integrityReport.firebasePlanNotes.activeProtectionStrategy}</p>
                <p className="text-slate-500">
                  Note: Google Cloud Firestore Managed Scheduled Backups and Point-in-Time Recovery
                  (PITR) require the Firebase Blaze (pay-as-you-go) plan and are never upgraded
                  automatically without explicit owner authorization.
                </p>
              </div>
            </>
          ) : (
            <div className="bg-white border border-slate-200 rounded-xl p-10 text-center text-sm text-slate-500">
              {loadingIntegrity
                ? 'Running read-only Firestore integrity audit...'
                : 'Click "Run Read-Only Integrity Audit" to inspect database health.'}
            </div>
          )}
        </div>
      )}

      {/* ==================================================================== */}
      {/* TAB 3: AUDIT LOGS */}
      {/* ==================================================================== */}
      {activeTab === 'audit' && (
        <div className="bg-white border border-slate-200 rounded-xl overflow-hidden">
          <div className="px-6 py-4 border-b border-slate-200 flex items-center justify-between">
            <div>
              <h2 className="font-display font-bold text-base text-[#0B1F3A]">
                Immutable Security & Certificate Audit Logs
              </h2>
              <p className="text-xs text-slate-500 mt-0.5">
                Records every authentication event, certificate issuance, edit, cancellation,
                deletion, backup, and credential rotation.
              </p>
            </div>
            <span className="text-xs font-mono text-slate-500 tabular-nums">
              {auditLogs.length} event(s)
            </span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-slate-200 bg-slate-50 font-semibold text-slate-600">
                  <th className="py-3 px-5">Timestamp</th>
                  <th className="py-3 px-4">Action</th>
                  <th className="py-3 px-4">Actor & Role</th>
                  <th className="py-3 px-4">Certificate</th>
                  <th className="py-3 px-4">Reason / Details</th>
                  <th className="py-3 px-5 text-right">IP Address</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200">
                {auditLogs.map((log) => (
                  <tr key={log.id} className="hover:bg-slate-50/70">
                    <td className="py-3 px-5 font-mono text-slate-600 whitespace-nowrap tabular-nums">
                      {new Date(log.timestamp).toLocaleString()}
                    </td>
                    <td className="py-3 px-4 font-mono font-semibold text-[#0B1F3A]">
                      {log.action}
                    </td>
                    <td className="py-3 px-4 text-slate-700">
                      <span className="font-medium">{log.actor}</span>
                      <span className="text-slate-400"> · {log.actorRole}</span>
                    </td>
                    <td className="py-3 px-4 font-mono text-slate-700">
                      {log.certificateNumber || '-'}
                    </td>
                    <td className="py-3 px-4 text-slate-600 max-w-xs truncate">
                      {log.reason || '-'}
                    </td>
                    <td className="py-3 px-5 font-mono text-slate-500 text-right">
                      {log.ipAddress || '-'}
                    </td>
                  </tr>
                ))}
                {auditLogs.length === 0 && (
                  <tr>
                    <td colSpan={6} className="py-8 text-center text-slate-500">
                      No audit logs recorded yet.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ==================================================================== */}
      {/* TAB 4: BACKUPS & DISASTER RECOVERY */}
      {/* ==================================================================== */}
      {activeTab === 'backups' && (
        <div className="space-y-6">
          <div className="bg-white border border-slate-200 rounded-xl p-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div>
              <h2 className="font-display font-bold text-base text-[#0B1F3A]">
                Verified Database Backups & Restore Dry-Run
              </h2>
              <p className="text-xs text-slate-600 mt-1">
                Every backup stores a SHA-256 cryptographic checksum independently of Vercel&apos;s
                ephemeral filesystem. Scheduled daily backups run via{' '}
                <code className="font-mono text-[#0B1F3A]">/api/cron/backup</code> protected by{' '}
                <code className="font-mono text-[#0B1F3A]">CRON_SECRET</code>.
              </p>
            </div>
            <button
              type="button"
              onClick={handleCreateBackup}
              disabled={backupBusy}
              className="inline-flex items-center gap-2 px-4 py-2.5 rounded-lg bg-[#059669] hover:bg-[#047857] text-white text-sm font-semibold transition-colors disabled:opacity-50 whitespace-nowrap shrink-0 cursor-pointer"
            >
              <Database className="w-4 h-4" />
              {backupBusy ? 'Creating Snapshot...' : 'Create Manual Verified Backup'}
            </button>
          </div>

          {/* Restore Dry-Run Analysis Card */}
          {dryRunResult && (
            <div className="bg-white border border-slate-300 rounded-xl p-6">
              <h3 className="font-display font-bold text-base text-[#0B1F3A]">
                Restore Dry-Run Verification — {dryRunResult.backupId}
              </h3>
              <div className="mt-4 grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs">
                <div className="p-3 bg-slate-50 border border-slate-200 rounded-lg">
                  <div className="text-slate-500">SHA-256 Checksum</div>
                  <div
                    className={`font-semibold mt-1 ${
                      dryRunResult.checksumValid ? 'text-[#059669]' : 'text-red-700'
                    }`}
                  >
                    {dryRunResult.checksumValid ? 'VERIFIED MATCH' : 'CORRUPTED'}
                  </div>
                </div>
                <div className="p-3 bg-slate-50 border border-slate-200 rounded-lg">
                  <div className="text-slate-500">Current vs Snapshot</div>
                  <div className="font-mono font-bold text-slate-900 mt-1 tabular-nums">
                    {dryRunResult.currentCertificateCount} → {dryRunResult.snapshotCertificateCount}
                  </div>
                </div>
                <div className="p-3 bg-slate-50 border border-slate-200 rounded-lg">
                  <div className="text-slate-500">Newer Records Affected</div>
                  <div className="font-mono font-bold text-slate-900 mt-1 tabular-nums">
                    {dryRunResult.certificatesOnlyInCurrent}
                  </div>
                </div>
                <div className="p-3 bg-slate-50 border border-slate-200 rounded-lg">
                  <div className="text-slate-500">Reserved Numbers Locked</div>
                  <div className="font-mono font-bold text-[#059669] mt-1 tabular-nums">
                    {dryRunResult.reservedNumbersPreserved} preserved
                  </div>
                </div>
              </div>

              {dryRunResult.warnings.length > 0 && (
                <div className="mt-4 p-3 rounded-lg bg-amber-50 border border-amber-200 text-xs text-amber-900 space-y-1">
                  {dryRunResult.warnings.map((w, idx) => (
                    <p key={idx}>{w}</p>
                  ))}
                </div>
              )}

              {dryRunResult.safeToRestore && (
                <form
                  onSubmit={handleExecuteRestore}
                  className="mt-5 pt-4 border-t border-slate-200 grid grid-cols-1 sm:grid-cols-3 gap-3 items-end"
                >
                  <div>
                    <label className="block text-xs font-medium text-slate-700 mb-1">
                      Type <span className="font-mono font-bold">CONFIRM RESTORE</span>
                    </label>
                    <input
                      type="text"
                      required
                      value={restoreConfirmPhrase}
                      onChange={(e) => setRestoreConfirmPhrase(e.target.value)}
                      placeholder="CONFIRM RESTORE"
                      className="w-full px-3 py-2 rounded-lg border border-slate-300 text-sm font-mono"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-slate-700 mb-1">
                      Protected Authorization Password
                    </label>
                    <input
                      type="password"
                      required
                      value={restorePassword}
                      onChange={(e) => setRestorePassword(e.target.value)}
                      placeholder="Protected password"
                      className="w-full px-3 py-2 rounded-lg border border-slate-300 text-sm"
                    />
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      type="submit"
                      disabled={backupBusy}
                      className="flex-1 py-2 px-4 rounded-lg bg-[#0B1F3A] hover:bg-[#132f57] text-white text-sm font-semibold cursor-pointer"
                    >
                      Execute Restore
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setDryRunResult(null);
                        setRestoreTargetId(null);
                      }}
                      className="py-2 px-3 rounded-lg border border-slate-300 text-sm text-slate-600 cursor-pointer"
                    >
                      Close
                    </button>
                  </div>
                </form>
              )}
            </div>
          )}

          {/* Isolated Staging Restore Verification Result Card */}
          {stagingResult && (
            <div className="bg-white border border-slate-300 rounded-xl p-6 space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div>
                  <h3 className="font-display font-bold text-base text-[#0B1F3A]">
                    Isolated Staging Restore Verification — {stagingResult.backupId}
                  </h3>
                  <p className="text-xs text-slate-500 mt-0.5">
                    Restored into an isolated ephemeral staging store without modifying any
                    production Firestore records.
                  </p>
                </div>
                <span
                  className={`px-3 py-1 rounded-full text-xs font-bold ${
                    stagingResult.safeForProductionRecovery
                      ? 'bg-emerald-100 text-emerald-800'
                      : 'bg-red-100 text-red-800'
                  }`}
                >
                  {stagingResult.safeForProductionRecovery
                    ? 'SAFE FOR PRODUCTION RECOVERY'
                    : 'BLOCKED — INTEGRITY ISSUES DETECTED'}
                </span>
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
                <div className="p-3 bg-slate-50 border border-slate-200 rounded-lg">
                  <div className="text-slate-500">Checksum</div>
                  <div
                    className={`font-semibold mt-1 ${
                      stagingResult.checksumValid ? 'text-[#059669]' : 'text-red-700'
                    }`}
                  >
                    {stagingResult.checksumValid ? 'SHA-256 VERIFIED' : 'MISMATCH'}
                  </div>
                </div>
                <div className="p-3 bg-slate-50 border border-slate-200 rounded-lg">
                  <div className="text-slate-500">Staging Restored</div>
                  <div className="font-mono font-bold text-[#0B1F3A] mt-1 tabular-nums">
                    {stagingResult.stagingRestoredCount} total ({stagingResult.stagingParivahanCount}{' '}
                    PS / {stagingResult.stagingScrapRouteCount} SR)
                  </div>
                </div>
                <div className="p-3 bg-slate-50 border border-slate-200 rounded-lg">
                  <div className="text-slate-500">Active / Archived</div>
                  <div className="font-mono font-bold text-slate-900 mt-1 tabular-nums">
                    {stagingResult.stagingActiveCount} / {stagingResult.stagingArchivedCount}
                  </div>
                </div>
                <div className="p-3 bg-slate-50 border border-slate-200 rounded-lg">
                  <div className="text-slate-500">Staging Integrity</div>
                  <div
                    className={`font-semibold mt-1 ${
                      stagingResult.stagingIntegrityHealthy ? 'text-[#059669]' : 'text-red-700'
                    }`}
                  >
                    {stagingResult.stagingIntegrityHealthy
                      ? '0 Mismatches'
                      : `${stagingResult.stagingIntegrityMismatches} Mismatch(es)`}
                  </div>
                </div>
              </div>

              {stagingResult.warnings.length > 0 && (
                <div className="p-3 rounded-lg bg-amber-50 border border-amber-200 text-xs text-amber-900 space-y-1">
                  {stagingResult.warnings.map((w, idx) => (
                    <p key={idx}>{w}</p>
                  ))}
                </div>
              )}

              <div className="flex justify-end">
                <button
                  type="button"
                  onClick={() => setStagingResult(null)}
                  className="px-3 py-1.5 rounded-lg border border-slate-300 text-xs font-semibold text-slate-700 cursor-pointer"
                >
                  Close Staging Report
                </button>
              </div>
            </div>
          )}

          {/* Snapshots Table */}
          <div className="bg-white border border-slate-200 rounded-xl overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="border-b border-slate-200 bg-slate-50 font-semibold text-slate-600">
                    <th className="py-3 px-5">Snapshot ID & Time</th>
                    <th className="py-3 px-4">Trigger</th>
                    <th className="py-3 px-4">Certificates / Reserved</th>
                    <th className="py-3 px-4">SHA-256 Checksum</th>
                    <th className="py-3 px-4">Size</th>
                    <th className="py-3 px-5 text-right">Recovery</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200">
                  {backups.map((b) => (
                    <tr key={b.id} className="hover:bg-slate-50/70">
                      <td className="py-3 px-5">
                        <div className="font-mono font-semibold text-[#0B1F3A]">{b.id}</div>
                        <div className="text-slate-500">{new Date(b.createdAt).toLocaleString()}</div>
                      </td>
                      <td className="py-3 px-4 font-mono text-slate-700">{b.trigger}</td>
                      <td className="py-3 px-4 font-mono tabular-nums text-slate-700">
                        {b.certificateCount} certs · {b.reservedCertCount} reserved
                      </td>
                      <td className="py-3 px-4 font-mono text-slate-600">
                        {b.sha256Checksum.slice(0, 20)}...
                      </td>
                      <td className="py-3 px-4 font-mono tabular-nums text-slate-600">
                        {(b.sizeBytes / 1024).toFixed(1)} KB
                      </td>
                      <td className="py-3 px-5 text-right">
                        <div className="inline-flex items-center gap-2 flex-wrap justify-end">
                          <button
                            type="button"
                            onClick={() => void api.downloadBackupJson(b.id)}
                            disabled={backupBusy}
                            className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-md border border-slate-300 bg-white hover:bg-slate-100 font-semibold text-slate-700 cursor-pointer"
                          >
                            <Download className="w-3 h-3" />
                            JSON
                          </button>
                          <button
                            type="button"
                            onClick={() => void handleStagingVerify(b.id)}
                            disabled={backupBusy}
                            className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-md border border-emerald-300 bg-emerald-50 hover:bg-emerald-100 font-semibold text-emerald-900 cursor-pointer"
                          >
                            <FlaskConical className="w-3 h-3" />
                            Verify in Staging
                          </button>
                          <button
                            type="button"
                            onClick={() => void handleDryRun(b.id)}
                            disabled={backupBusy}
                            className="px-3 py-1.5 rounded-md border border-slate-300 bg-white hover:bg-slate-100 font-semibold text-[#0B1F3A] cursor-pointer"
                          >
                            Restore Dry-Run
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                  {backups.length === 0 && (
                    <tr>
                      <td colSpan={6} className="py-8 text-center text-slate-500">
                        No backup snapshots created yet. Zero old backups imported.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* ==================================================================== */}
      {/* TAB 5: SETTINGS, GOOGLE DRIVE, PASSWORD ROTATION & HEALTH */}
      {/* ==================================================================== */}
      {activeTab === 'settings' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Left Column: Facility & Drive Settings */}
          <div className="lg:col-span-7 space-y-6">
            {settings && (
              <form
                onSubmit={handleSaveSettings}
                className="bg-white border border-slate-200 rounded-xl p-6 space-y-4"
              >
                <h2 className="font-display font-bold text-base text-[#0B1F3A]">
                  Facility Branding, Backup Retention & Google Drive Sync
                </h2>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-xs font-medium text-slate-700 mb-1">
                      Facility Name
                    </label>
                    <input
                      type="text"
                      value={settings.facilityName}
                      onChange={(e) => setSettings({ ...settings, facilityName: e.target.value })}
                      className="w-full px-3 py-2 rounded-lg border border-slate-300 text-sm"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-slate-700 mb-1">
                      RVSF Registration Code
                    </label>
                    <input
                      type="text"
                      value={settings.facilityRvsfCode}
                      onChange={(e) =>
                        setSettings({ ...settings, facilityRvsfCode: e.target.value })
                      }
                      className="w-full px-3 py-2 rounded-lg border border-slate-300 text-sm font-mono"
                    />
                  </div>
                  <div className="sm:col-span-2">
                    <label className="block text-xs font-medium text-slate-700 mb-1">
                      Facility Address
                    </label>
                    <input
                      type="text"
                      value={settings.facilityAddress}
                      onChange={(e) =>
                        setSettings({ ...settings, facilityAddress: e.target.value })
                      }
                      className="w-full px-3 py-2 rounded-lg border border-slate-300 text-sm"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-slate-700 mb-1">
                      Authorized Signatory Name
                    </label>
                    <input
                      type="text"
                      value={settings.authorizedSignatory}
                      onChange={(e) =>
                        setSettings({ ...settings, authorizedSignatory: e.target.value })
                      }
                      className="w-full px-3 py-2 rounded-lg border border-slate-300 text-sm"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-slate-700 mb-1">
                      Backup Retention Policy (Days)
                    </label>
                    <input
                      type="number"
                      min={7}
                      max={3650}
                      value={settings.backupRetentionDays}
                      onChange={(e) =>
                        setSettings({
                          ...settings,
                          backupRetentionDays: Number(e.target.value),
                        })
                      }
                      className="w-full px-3 py-2 rounded-lg border border-slate-300 text-sm font-mono"
                    />
                  </div>
                  <div className="sm:col-span-2">
                    <label className="block text-xs font-medium text-slate-700 mb-1">
                      Public QR Verification Domain (defaults to PUBLIC_APP_URL or current origin)
                    </label>
                    <input
                      type="url"
                      value={settings.publicDomain}
                      onChange={(e) => setSettings({ ...settings, publicDomain: e.target.value })}
                      placeholder="https://parivahan-certificate-fresh.vercel.app"
                      className="w-full px-3 py-2 rounded-lg border border-slate-300 text-sm font-mono"
                    />
                  </div>
                </div>

                {/* Optional Independent Google Drive Section */}
                <div className="pt-4 border-t border-slate-200 space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <FolderSync className="w-4 h-4 text-[#059669]" />
                      <span className="text-sm font-semibold text-[#0B1F3A]">
                        Optional Independent Google Drive Sync
                      </span>
                    </div>
                    <label className="inline-flex items-center gap-2 text-xs font-medium text-slate-700 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={settings.driveSyncEnabled}
                        onChange={(e) =>
                          setSettings({ ...settings, driveSyncEnabled: e.target.checked })
                        }
                        className="rounded border-slate-300"
                      />
                      Enable Non-Blocking Sync
                    </label>
                  </div>
                  <p className="text-xs text-slate-500">
                    Runs asynchronously after Firestore commit so certificate issuance is never
                    blocked. Service Account credentials:{' '}
                    <span className="font-semibold text-slate-700">
                      {driveEnvConfigured ? 'Configured via Environment' : 'Not Configured'}
                    </span>
                  </p>
                  <div>
                    <label className="block text-xs font-medium text-slate-700 mb-1">
                      New Dedicated Google Drive Folder ID (Optional)
                    </label>
                    <input
                      type="text"
                      value={settings.driveFolderId}
                      onChange={(e) =>
                        setSettings({ ...settings, driveFolderId: e.target.value })
                      }
                      placeholder="Leave blank to disable Drive archival"
                      className="w-full px-3 py-2 rounded-lg border border-slate-300 text-sm font-mono"
                    />
                  </div>
                </div>

                <div className="pt-2 flex justify-end">
                  <button
                    type="submit"
                    className="px-5 py-2 rounded-lg bg-[#0B1F3A] hover:bg-[#132f57] text-white text-sm font-semibold cursor-pointer"
                  >
                    Save Configuration
                  </button>
                </div>
              </form>
            )}

            {/* Password Rotation & Session Invalidation */}
            <div className="bg-white border border-slate-200 rounded-xl p-6">
              <div className="flex items-center gap-2 mb-2">
                <KeyRound className="w-4 h-4 text-[#059669]" />
                <h2 className="font-display font-bold text-base text-[#0B1F3A]">
                  Password Rotation & Global Session Invalidation
                </h2>
              </div>

              <div className="mb-3 rounded-lg bg-slate-50 border border-slate-200 px-3.5 py-2.5 text-xs text-slate-600 flex flex-wrap items-center justify-between gap-2">
                <span>
                  Active Maker Username:{' '}
                  <strong className="font-mono text-[#0B1F3A]">
                    {activeMakerUsername || 'Not configured'}
                  </strong>
                </span>
                <span>
                  Authoritative Auth Source:{' '}
                  <strong className="font-mono text-[#059669]">
                    Firestore admins/primary_credentials (All Accounts)
                  </strong>
                </span>
              </div>

              {staleMakerEnvIgnored && (
                <div className="mb-3 rounded-lg bg-amber-50 border border-amber-200 px-3.5 py-2.5 text-xs text-amber-900">
                  Note: Legacy password or username environment variables (
                  <code className="font-mono">ADMIN_PASSWORD</code>,{' '}
                  <code className="font-mono">ADMIN_USERNAME</code>, or{' '}
                  <code className="font-mono">MAIN_ADMIN_PASSWORD</code>) are automatically ignored
                  because Firestore <code className="font-mono">admins/primary_credentials</code> is
                  the single authoritative source of truth for authentication.
                </div>
              )}

              <form onSubmit={handleRotatePasswords} className="mt-4 space-y-3.5">
                <p className="text-xs text-slate-600 leading-relaxed">
                  Rotate credentials directly in Firestore{' '}
                  <code className="font-mono">admins/primary_credentials</code> using salted scrypt.
                  Entering only the Maker password updates ONLY the Maker hash while keeping the
                  username (
                  <strong className="font-mono">{activeMakerUsername || 'user-pscrappers'}</strong>)
                  and Main Core Admin credentials untouched.
                </p>
                <div>
                  <label className="block text-xs font-medium text-slate-700 mb-1">
                    Current Main Core Admin Password <span className="text-red-600">*</span>
                  </label>
                  <input
                    type="password"
                    required
                    value={currentMainPassword}
                    onChange={(e) => setCurrentMainPassword(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg border border-slate-300 text-sm"
                  />
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label className="block text-xs font-medium text-slate-700 mb-1">
                      New Maker Password
                    </label>
                    <input
                      type="password"
                      minLength={8}
                      value={newMakerPassword}
                      onChange={(e) => setNewMakerPassword(e.target.value)}
                      placeholder="Minimum 8 characters"
                      className="w-full px-3 py-2 rounded-lg border border-slate-300 text-sm"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-slate-700 mb-1">
                      Confirm New Maker Password
                    </label>
                    <input
                      type="password"
                      minLength={8}
                      value={confirmMakerPassword}
                      onChange={(e) => setConfirmMakerPassword(e.target.value)}
                      placeholder="Re-enter new Maker password"
                      className="w-full px-3 py-2 rounded-lg border border-slate-300 text-sm"
                    />
                  </div>
                </div>
                {!envManagedCreds && (
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div>
                      <label className="block text-xs font-medium text-slate-700 mb-1">
                        New Admin Password (Optional)
                      </label>
                      <input
                        type="password"
                        minLength={8}
                        value={newMainAdminPassword}
                        onChange={(e) => setNewMainAdminPassword(e.target.value)}
                        placeholder="Leave blank to keep unchanged"
                        className="w-full px-3 py-2 rounded-lg border border-slate-300 text-sm"
                      />
                    </div>
                    <div>
                      <label className="block text-xs font-medium text-slate-700 mb-1">
                        New Protected Password (Optional)
                      </label>
                      <input
                        type="password"
                        minLength={8}
                        value={newProtectedPassword}
                        onChange={(e) => setNewProtectedPassword(e.target.value)}
                        placeholder="Leave blank to keep unchanged"
                        className="w-full px-3 py-2 rounded-lg border border-slate-300 text-sm"
                      />
                    </div>
                  </div>
                )}
                <div className="flex justify-end">
                  <button
                    type="submit"
                    className="px-4 py-2 rounded-lg bg-[#059669] hover:bg-[#047857] text-white text-sm font-semibold cursor-pointer"
                  >
                    Rotate Password & Invalidate Old Sessions
                  </button>
                </div>
              </form>
            </div>
          </div>

          {/* Right Column: Platform Health & Error Logs */}
          <div className="lg:col-span-5 space-y-6">
            <div className="bg-white border border-slate-200 rounded-xl p-6">
              <div className="flex items-center gap-2 mb-4">
                <Activity className="w-4 h-4 text-[#059669]" />
                <h2 className="font-display font-bold text-base text-[#0B1F3A]">
                  Platform Health & Storage Backend
                </h2>
              </div>

              {healthInfo && (
                <dl className="space-y-3 text-xs">
                  <div className="flex justify-between py-2 border-b border-slate-100">
                    <dt className="text-slate-500">Storage Mode</dt>
                    <dd className="font-mono font-semibold text-[#0B1F3A] text-right">
                      {healthInfo.storageMode === 'firestore'
                        ? `Google Cloud Firestore (${healthInfo.storageLatencyMs}ms)`
                        : healthInfo.storageMode === 'firestore_unconfigured'
                          ? 'Awaiting Vercel Firestore Env Vars'
                          : 'Dev Staging Memory (Set FIREBASE_* on Vercel)'}
                    </dd>
                  </div>
                  <div className="flex justify-between py-2 border-b border-slate-100 gap-4">
                    <dt className="text-slate-500 shrink-0">Connection Probe</dt>
                    <dd className="text-slate-700 text-right">{healthInfo.storageMessage}</dd>
                  </div>
                  {healthInfo.firestoreProjectId && (
                    <div className="flex justify-between py-2 border-b border-slate-100">
                      <dt className="text-slate-500">Firestore Project / DB</dt>
                      <dd className="font-mono text-slate-800">
                        {healthInfo.firestoreProjectId} / {healthInfo.firestoreDatabaseId}
                      </dd>
                    </div>
                  )}
                  <div className="flex justify-between py-2 border-b border-slate-100">
                    <dt className="text-slate-500">Node.js Runtime</dt>
                    <dd className="font-mono text-slate-800">{healthInfo.nodeVersion}</dd>
                  </div>
                  <div className="flex justify-between py-2 border-b border-slate-100">
                    <dt className="text-slate-500">Reserved Cert / Reg Numbers</dt>
                    <dd className="font-mono tabular-nums text-slate-800">
                      {healthInfo.reservedCertNumbers} / {healthInfo.reservedRegNumbers}
                    </dd>
                  </div>
                  <div className="flex justify-between py-2">
                    <dt className="text-slate-500">Recorded System Errors</dt>
                    <dd className="font-mono tabular-nums text-slate-800">
                      {healthInfo.recentErrors.length}
                    </dd>
                  </div>
                </dl>
              )}
            </div>

            <div className="bg-white border border-slate-200 rounded-xl p-6">
              <h3 className="font-display font-bold text-sm text-[#0B1F3A] mb-3">
                Recent Google Drive Sync Logs
              </h3>
              {healthInfo && healthInfo.driveLogs.length > 0 ? (
                <div className="space-y-2 text-xs">
                  {healthInfo.driveLogs.slice(0, 8).map((log) => (
                    <div
                      key={log.id}
                      className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 flex items-center justify-between gap-2"
                    >
                      <div>
                        <span className="font-mono font-semibold text-[#0B1F3A]">
                          {log.certificateNumber}
                        </span>
                        <span className="text-slate-500 ml-2">{log.status}</span>
                      </div>
                      {log.status === 'FAILED' && (
                        <button
                          type="button"
                          onClick={() => void api.retryDriveSync(log.certificateId)}
                          className="text-[#059669] font-semibold hover:underline cursor-pointer"
                        >
                          Retry
                        </button>
                      )}
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-xs text-slate-500">
                  No Google Drive sync attempts logged. Drive integration is independent and
                  optional.
                </p>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Protected Edit / Cancel / Archive / Permanent Delete / Restore Modal */}
      <ProtectedActionModal
        key={`${actionCert?.id ?? 'none'}_${actionMode ?? 'none'}`}
        certificate={actionCert}
        mode={actionMode}
        onClose={() => {
          setActionCert(null);
          setActionMode(null);
        }}
        onSuccess={async () => {
          setBanner({ type: 'success', text: 'Protected action authorized and recorded in audit logs.' });
          await Promise.all([loadRegistryAndStats(), loadAuditLogs()]);
        }}
      />

      {/* Immutable Certificate Version History Modal */}
      {(historyPayload || historyLoading) && (
        <div
          className="fixed inset-0 z-50 bg-slate-900/60 flex items-center justify-center p-4 overflow-y-auto"
          role="dialog"
          aria-modal="true"
        >
          <div className="bg-white rounded-xl border border-slate-200 w-full max-w-3xl max-h-[90vh] overflow-y-auto shadow-2xl">
            <div className="px-6 py-4 bg-[#0B1F3A] text-white flex items-center justify-between sticky top-0 z-10">
              <div className="flex items-center gap-2.5">
                <History className="w-5 h-5 text-emerald-400" />
                <div>
                  <h3 className="font-display font-bold text-base">
                    Immutable Certificate Version History
                  </h3>
                  {historyPayload && (
                    <p className="text-xs font-mono text-slate-300">
                      {historyPayload.certificate.certificateNumber} · Current v
                      {historyPayload.certificate.version} · Status:{' '}
                      {historyPayload.certificate.status === 'SOFT_DELETED'
                        ? 'ARCHIVED'
                        : historyPayload.certificate.status}
                    </p>
                  )}
                </div>
              </div>
              <button
                type="button"
                onClick={() => {
                  setHistoryPayload(null);
                  setHistoryError(null);
                }}
                className="p-1.5 rounded-lg text-slate-300 hover:bg-white/10 cursor-pointer"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="p-6 space-y-5 text-xs">
              {historyLoading ? (
                <div className="py-10 text-center text-slate-500">
                  Loading immutable version records from Firestore...
                </div>
              ) : historyError ? (
                <div className="p-4 rounded-lg bg-red-50 border border-red-200 text-red-800">
                  {historyError}
                </div>
              ) : historyPayload ? (
                <>
                  {/* Immutable Version 1 Original Issuance Card */}
                  <div className="rounded-xl border border-emerald-200 bg-emerald-50/50 p-4 space-y-2.5">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="font-bold text-[#065F46] uppercase tracking-wider text-[11px]">
                        Immutable Original Record (Version 1)
                      </span>
                      <span className="font-mono text-slate-600">
                        Issued {new Date(historyPayload.originalRecord.issuedAt).toLocaleString()} by{' '}
                        {historyPayload.originalRecord.issuedBy}
                      </span>
                    </div>
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-slate-800">
                      <div>
                        <span className="text-slate-500">Owner:</span>{' '}
                        <span className="font-semibold">
                          {historyPayload.originalRecord.data.ownerName}
                        </span>
                      </div>
                      <div>
                        <span className="text-slate-500">Vehicle RC:</span>{' '}
                        <span className="font-mono font-semibold">
                          {historyPayload.originalRecord.data.vehicleRegNumber}
                        </span>
                      </div>
                      <div>
                        <span className="text-slate-500">Make/Model:</span>{' '}
                        <span>
                          {historyPayload.originalRecord.data.make}{' '}
                          {historyPayload.originalRecord.data.model} (
                          {historyPayload.originalRecord.data.manufactureYear})
                        </span>
                      </div>
                    </div>
                    <div className="font-mono text-[11px] text-slate-600 break-all">
                      Original SHA-256: {historyPayload.originalRecord.canonicalHash}
                    </div>
                  </div>

                  {/* Embedded Version Diffs */}
                  <div className="space-y-2.5">
                    <h4 className="font-display font-bold text-sm text-[#0B1F3A]">
                      Modification Snapshots ({historyPayload.versionHistory.length})
                    </h4>
                    {historyPayload.versionHistory.length === 0 ? (
                      <p className="text-slate-500 p-3 rounded-lg bg-slate-50 border border-slate-200">
                        No modifications have been made since original issuance (Version 1 remains
                        current).
                      </p>
                    ) : (
                      historyPayload.versionHistory.map((snap, idx) => (
                        <div
                          key={`${snap.version}_${snap.editedAt}_${idx}`}
                          className="rounded-lg border border-slate-200 bg-white p-4 space-y-1.5"
                        >
                          <div className="flex flex-wrap items-center justify-between gap-2">
                            <span className="font-mono font-bold text-[#0B1F3A]">
                              Archived v{snap.version} → Updated
                            </span>
                            <span className="text-slate-500 font-mono">
                              {new Date(snap.editedAt).toLocaleString()} · {snap.editedBy}
                              {snap.actorRole ? ` (${snap.actorRole})` : ''}
                            </span>
                          </div>
                          <p className="text-slate-700">
                            <span className="font-semibold">Reason:</span> {snap.reason}
                          </p>
                          {snap.changedFields && snap.changedFields.length > 0 && (
                            <p className="text-slate-700">
                              <span className="font-semibold">Changed Fields:</span>{' '}
                              <span className="font-mono text-[#0B1F3A]">
                                {snap.changedFields.join(', ')}
                              </span>
                            </p>
                          )}
                          <div className="font-mono text-[11px] text-slate-500 break-all">
                            Prev Hash: {snap.previousCanonicalHash}
                            {snap.newCanonicalHash ? ` → New Hash: ${snap.newCanonicalHash}` : ''}
                          </div>
                        </div>
                      ))
                    )}
                  </div>

                  {/* Append-Only Version Collection Events */}
                  {historyPayload.appendOnlyVersions.length > 0 && (
                    <div className="space-y-2">
                      <h4 className="font-display font-bold text-sm text-[#0B1F3A]">
                        Append-Only Lifecycle Ledger ({historyPayload.appendOnlyVersions.length})
                      </h4>
                      <div className="divide-y divide-slate-200 rounded-lg border border-slate-200 overflow-hidden">
                        {historyPayload.appendOnlyVersions.map((ev) => (
                          <div
                            key={ev.id}
                            className="p-3 bg-slate-50/70 flex flex-col sm:flex-row sm:items-center justify-between gap-2"
                          >
                            <div>
                              <span className="font-mono font-bold text-[#0B1F3A] mr-2">
                                v{ev.version} · {ev.event}
                              </span>
                              <span className="text-slate-600">
                                by {ev.actor} ({ev.actorRole})
                              </span>
                              {ev.reason && (
                                <div className="text-slate-500 mt-0.5">Reason: {ev.reason}</div>
                              )}
                            </div>
                            <span className="font-mono text-[11px] text-slate-500 whitespace-nowrap">
                              {new Date(ev.recordedAt).toLocaleString()}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </>
              ) : null}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
