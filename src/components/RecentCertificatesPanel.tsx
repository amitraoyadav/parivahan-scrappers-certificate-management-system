import React, { useState } from 'react';
import {
  AlertTriangle,
  Archive,
  CheckCircle2,
  Download,
  ExternalLink,
  Eye,
  FileText,
  Pencil,
  RefreshCw,
  X,
} from 'lucide-react';
import type { CertificateRecord } from '../shared/types';
import {
  downloadCertificatePdf,
  getCertificateBrand,
  type PdfBrandingOptions,
} from '../lib/pdfGenerator';

interface RecentCertificatesPanelProps {
  certificates: CertificateRecord[];
  loading: boolean;
  hasLoadedOnce?: boolean;
  syncStatus?: 'idle' | 'syncing' | 'synced' | 'error';
  lastSyncedAt?: string | null;
  syncError?: string | null;
  onRetrySync?: () => void;
  onPreview: (cert: CertificateRecord) => void;
  onEdit: (cert: CertificateRecord) => void;
  onDelete: (cert: CertificateRecord) => Promise<void>;
  onOpenVerify: (cert: CertificateRecord) => void;
  pdfBranding?: PdfBrandingOptions;
}

export const RecentCertificatesPanel: React.FC<RecentCertificatesPanelProps> = ({
  certificates,
  loading,
  hasLoadedOnce = true,
  syncStatus = 'idle',
  lastSyncedAt = null,
  syncError = null,
  onRetrySync,
  onPreview,
  onEdit,
  onDelete,
  onOpenVerify,
  pdfBranding,
}) => {
  const [confirmDeleteCert, setConfirmDeleteCert] = useState<CertificateRecord | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);

  const handleConfirmDelete = async () => {
    if (!confirmDeleteCert || deleting) return;
    setDeleting(true);
    setDeleteError(null);
    try {
      await onDelete(confirmDeleteCert);
      setConfirmDeleteCert(null);
    } catch (err) {
      setDeleteError(err instanceof Error ? err.message : 'Unable to archive certificate.');
    } finally {
      setDeleting(false);
    }
  };

  return (
    <>
      <section className="bg-white border border-slate-200 rounded-xl overflow-hidden">
        <div className="px-6 py-4 border-b border-slate-200 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div>
            <h2 className="font-display text-base font-bold text-[#0B1F3A]">
              Latest Five Issued Certificates
            </h2>
            <p className="text-xs text-slate-500 mt-0.5">
              Certificate Maker visibility is restricted to the 5 most recently issued records. You
              can preview, download, edit, or archive recent certificates. Permanent deletion is
              restricted to Main Core Admin.
            </p>
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
                    : 'Database Connected'}
            </span>
            <span className="text-xs font-mono text-slate-500 tabular-nums">
              Showing {certificates.length} / 5 max
            </span>
          </div>
        </div>

        {syncError && (
          <div
            role="alert"
            className="px-6 py-3.5 bg-red-50 border-b border-red-200 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs text-red-900"
          >
            <div className="flex items-start gap-2 font-semibold">
              <AlertTriangle className="w-4 h-4 shrink-0 text-red-600 mt-0.5" />
              <span>{syncError}</span>
            </div>
            {onRetrySync && (
              <button
                type="button"
                onClick={onRetrySync}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-white border border-red-300 hover:bg-red-100 text-red-800 font-semibold whitespace-nowrap shrink-0 cursor-pointer"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                Retry Sync
              </button>
            )}
          </div>
        )}

        {loading && !hasLoadedOnce ? (
          <div className="p-8 text-center text-sm text-slate-500">Synchronizing recent certificates from Firestore...</div>
        ) : certificates.length === 0 && syncError ? (
          <div className="p-10 text-center">
            <p className="font-semibold text-sm text-red-800">
              SYNC ERROR — EXISTING DATABASE RECORDS HAVE BEEN PRESERVED.
            </p>
            <p className="text-xs text-slate-600 mt-1 max-w-md mx-auto">
              Unable to reach the database right now. Your existing certificates have not been
              modified or deleted. Click Retry Sync to reconnect.
            </p>
          </div>
        ) : certificates.length === 0 && hasLoadedOnce ? (
          <div className="p-10 text-center">
            <div className="w-10 h-10 rounded-lg bg-slate-100 text-slate-500 mx-auto flex items-center justify-center mb-3">
              <FileText className="w-5 h-5" />
            </div>
            <p className="font-medium text-sm text-slate-900">No Active Certificates Yet</p>
            <p className="text-xs text-slate-500 mt-1 max-w-md mx-auto">
              Complete the form above to issue a vehicle scrapping certificate. Every issued record
              is permanently persisted in Firestore.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-sm">
              <thead>
                <tr className="border-b border-slate-200 bg-slate-50 text-xs font-semibold text-slate-600">
                  <th className="py-3 px-6">Certificate & Reg. No.</th>
                  <th className="py-3 px-4">Owner</th>
                  <th className="py-3 px-4">Vehicle</th>
                  <th className="py-3 px-4">Issue Date</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-6 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200">
                {certificates.map((cert) => {
                  const isSr = getCertificateBrand(cert) === 'scrap_route';
                  return (
                  <tr key={cert.id} className="hover:bg-slate-50/70 transition-colors">
                    <td className="py-3.5 px-6">
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
                        {cert.make} {cert.model} · {cert.manufactureYear}
                      </div>
                    </td>
                    <td className="py-3.5 px-4 font-mono text-xs text-slate-700 tabular-nums">
                      <div>{cert.issueDate}</div>
                      {cert.version > 1 && (
                        <div className="text-[11px] text-slate-400">v{cert.version}</div>
                      )}
                    </td>
                    <td className="py-3.5 px-4">
                      <span
                        className={`text-xs font-semibold ${
                          cert.status === 'ACTIVE' ? 'text-[#059669]' : 'text-red-700'
                        }`}
                      >
                        {cert.status}
                      </span>
                    </td>
                    <td className="py-3.5 px-6 text-right">
                      <div className="inline-flex items-center gap-1.5 flex-wrap justify-end">
                        <button
                          type="button"
                          onClick={() => onPreview(cert)}
                          className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-md border border-slate-300 bg-white hover:bg-slate-100 text-xs font-medium text-slate-700 cursor-pointer whitespace-nowrap"
                        >
                          <Eye className="w-3.5 h-3.5" />
                          View
                        </button>
                        <button
                          type="button"
                          onClick={() => void downloadCertificatePdf(cert, pdfBranding)}
                          className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-md bg-[#0B1F3A] hover:bg-[#132f57] text-xs font-medium text-white cursor-pointer whitespace-nowrap"
                        >
                          <Download className="w-3.5 h-3.5" />
                          PDF
                        </button>
                        {cert.status === 'ACTIVE' && (
                          <button
                            type="button"
                            onClick={() => onEdit(cert)}
                            className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-md border border-slate-300 bg-white hover:bg-slate-100 text-xs font-medium text-slate-700 cursor-pointer whitespace-nowrap"
                          >
                            <Pencil className="w-3.5 h-3.5" />
                            Edit
                          </button>
                        )}
                        {cert.status !== 'SOFT_DELETED' && (
                          <button
                            type="button"
                            onClick={() => {
                              setDeleteError(null);
                              setConfirmDeleteCert(cert);
                            }}
                            className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-md border border-amber-200 bg-amber-50 hover:bg-amber-100 text-xs font-medium text-amber-800 cursor-pointer whitespace-nowrap"
                          >
                            <Archive className="w-3.5 h-3.5" />
                            Archive
                          </button>
                        )}
                        <button
                          type="button"
                          onClick={() => onOpenVerify(cert)}
                          title="Open public QR verification view"
                          className="p-1.5 rounded-md border border-slate-300 bg-white hover:bg-slate-100 text-slate-600 cursor-pointer"
                        >
                          <ExternalLink className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* Reversible Archive Confirmation Modal (Maker cannot permanently delete) */}
      {confirmDeleteCert && (
        <div
          className="fixed inset-0 z-50 bg-slate-900/60 flex items-center justify-center p-4"
          role="dialog"
          aria-modal="true"
          aria-labelledby="maker-delete-title"
        >
          <div className="bg-white rounded-xl border border-slate-200 w-full max-w-md shadow-2xl overflow-hidden">
            <div className="px-5 py-4 bg-amber-700 text-white flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Archive className="w-5 h-5 text-amber-100" />
                <h3 id="maker-delete-title" className="font-display font-bold text-base">
                  Archive Certificate?
                </h3>
              </div>
              <button
                type="button"
                disabled={deleting}
                onClick={() => setConfirmDeleteCert(null)}
                className="p-1 rounded-md text-amber-100 hover:bg-white/15 cursor-pointer disabled:opacity-50"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-5 space-y-4">
              <p className="text-sm text-slate-700 leading-relaxed">
                Archiving removes this certificate from active Maker views and public QR
                verification without deleting any database data. The complete record and version
                history remain preserved in Firestore, its certificate number remains permanently
                reserved, and Main Core Admin can restore it at any time.
              </p>

              <div className="rounded-lg bg-slate-50 border border-slate-200 px-3.5 py-3 text-xs space-y-1">
                <div className="flex justify-between gap-3">
                  <span className="text-slate-500">Certificate No.</span>
                  <span className="font-mono font-bold text-[#0B1F3A]">
                    {confirmDeleteCert.certificateNumber}
                  </span>
                </div>
                <div className="flex justify-between gap-3">
                  <span className="text-slate-500">Owner</span>
                  <span className="font-medium text-slate-900">{confirmDeleteCert.ownerName}</span>
                </div>
                <div className="flex justify-between gap-3">
                  <span className="text-slate-500">Vehicle Reg. No.</span>
                  <span className="font-mono font-semibold text-slate-800">
                    {confirmDeleteCert.vehicleRegNumber}
                  </span>
                </div>
              </div>

              {deleteError && (
                <div className="p-3 rounded-lg bg-red-50 border border-red-200 text-red-800 text-xs">
                  {deleteError}
                </div>
              )}

              <div className="flex justify-end gap-2 pt-1">
                <button
                  type="button"
                  disabled={deleting}
                  onClick={() => setConfirmDeleteCert(null)}
                  className="px-4 py-2 rounded-lg border border-slate-300 bg-white hover:bg-slate-50 text-sm font-medium text-slate-700 cursor-pointer disabled:opacity-50"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  disabled={deleting}
                  onClick={() => void handleConfirmDelete()}
                  className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-amber-700 hover:bg-amber-800 text-white text-sm font-semibold cursor-pointer disabled:opacity-50"
                >
                  <Archive className="w-4 h-4" />
                  {deleting ? 'Archiving...' : 'Archive Certificate'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </>
  );
};

