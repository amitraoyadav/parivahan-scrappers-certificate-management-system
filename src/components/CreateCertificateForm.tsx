import React, { useCallback, useEffect, useRef, useState } from 'react';
import {
  AlertCircle,
  CheckCircle2,
  Download,
  ExternalLink,
  Eye,
  EyeOff,
  FilePlus2,
  RefreshCw,
} from 'lucide-react';
import type {
  CandidateNumbers,
  CertificateRecord,
  CreateCertificateInput,
  IdProofType,
} from '../shared/types';
import {
  OTHER_MANUFACTURER_VALUE,
  VEHICLE_MANUFACTURER_GROUPS,
  formatChassisOrEngine,
} from '../shared/vehicleData';
import { api, ApiError } from '../lib/api';
import {
  downloadCertificatePdf,
  openAndDownloadCertificatePdf,
  type PdfBrandingOptions,
} from '../lib/pdfGenerator';

interface CreateCertificateFormProps {
  onCertificateCreated: (cert: CertificateRecord) => void;
  onPreviewCertificate: (cert: CertificateRecord) => void;
  onSessionExpired?: () => void;
  pdfBranding?: PdfBrandingOptions;
}

const ID_PROOF_OPTIONS: Array<{ value: IdProofType; label: string }> = [
  { value: '', label: '-- Not Provided (Optional) --' },
  { value: 'Aadhaar Card', label: 'Aadhaar Card' },
  { value: 'PAN Card', label: 'PAN Card' },
  { value: 'Driving License', label: 'Driving License' },
  { value: 'Passport', label: 'Passport' },
  { value: 'Voter ID', label: 'Voter ID' },
];

function todayIso(): string {
  return new Date().toISOString().slice(0, 10);
}

function createInitialForm(): CreateCertificateInput {
  const today = todayIso();
  return {
    issueDate: today,
    handoverDate: today,
    ownerName: '',
    ownerAddress: '',
    idProofType: '',
    idProofNumber: '',
    vehicleRegNumber: '',
    make: '',
    model: '',
    manufactureYear: 2012,
    chassisNumber: '',
    engineNumber: '',
    unhideChassisEngine: false,
    remarks: '',
  };
}

function createIdempotencyKey(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return `cert_req_${crypto.randomUUID()}`;
  }
  return `cert_req_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;
}

export const CreateCertificateForm: React.FC<CreateCertificateFormProps> = ({
  onCertificateCreated,
  onPreviewCertificate,
  onSessionExpired,
  pdfBranding,
}) => {
  const [form, setForm] = useState<CreateCertificateInput>(createInitialForm);
  const [selectedMakeOption, setSelectedMakeOption] = useState<string>('');
  const [customMake, setCustomMake] = useState<string>('');
  const [candidates, setCandidates] = useState<CandidateNumbers | null>(null);
  const [loadingCandidates, setLoadingCandidates] = useState(false);
  const [candidateError, setCandidateError] = useState<string | null>(null);
  const [sessionExpired, setSessionExpired] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastIssued, setLastIssued] = useState<{
    certificate: CertificateRecord;
    persistenceMs: number;
    idempotentReplay: boolean;
    pdfFileName?: string;
    pdfBlobUrl?: string;
    popupBlocked?: boolean;
    pdfFailed?: boolean;
  } | null>(null);

  // Persistent idempotency key for the active form submission so retries/double-clicks never duplicate
  const idempotencyKeyRef = useRef<string>(createIdempotencyKey());
  const inFlightRef = useRef<boolean>(false);
  const lastBlobUrlRef = useRef<string | null>(null);

  useEffect(() => {
    return () => {
      if (lastBlobUrlRef.current) {
        URL.revokeObjectURL(lastBlobUrlRef.current);
      }
    };
  }, []);

  const loadCandidates = useCallback(async (issueDate?: string) => {
    setLoadingCandidates(true);
    setCandidateError(null);
    try {
      const next = await api.getCandidateNumbers(issueDate);
      setCandidates(next);
      setSessionExpired(false);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        setSessionExpired(true);
        setCandidateError('Session expired. Please sign in again.');
      } else {
        setCandidateError(
          err instanceof ApiError
            ? err.message
            : 'Unable to load next available numbers. Click Retry.'
        );
      }
    } finally {
      setLoadingCandidates(false);
    }
  }, []);

  useEffect(() => {
    void loadCandidates(form.issueDate);
  }, [loadCandidates, form.issueDate]);

  const updateField = <K extends keyof CreateCertificateInput>(
    key: K,
    value: CreateCertificateInput[K]
  ) => {
    setForm((prev) => ({ ...prev, [key]: value }));
  };

  const handleMakeDropdownChange = (val: string) => {
    setSelectedMakeOption(val);
    if (val === OTHER_MANUFACTURER_VALUE) {
      updateField('make', customMake);
    } else {
      setCustomMake('');
      updateField('make', val);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (inFlightRef.current || submitting) return;

    setError(null);
    inFlightRef.current = true;
    setSubmitting(true);

    try {
      const effectiveMake =
        selectedMakeOption === OTHER_MANUFACTURER_VALUE ? customMake.trim() : form.make.trim();

      const result = await api.createCertificate(
        {
          ...form,
          make: effectiveMake,
          certificateNumber: candidates?.certificateNumber,
          scrappingRegNumber: candidates?.scrappingRegNumber,
        },
        idempotencyKeyRef.current
      );

      // Authoritative persistence confirmed!
      onCertificateCreated(result.certificate);

      // Automatically generate, open in a new tab, and download the official PDF
      let pdfMeta: {
        pdfFileName?: string;
        pdfBlobUrl?: string;
        popupBlocked?: boolean;
        pdfFailed?: boolean;
      } = {};
      try {
        if (lastBlobUrlRef.current) {
          URL.revokeObjectURL(lastBlobUrlRef.current);
          lastBlobUrlRef.current = null;
        }
        const generated = await openAndDownloadCertificatePdf(result.certificate, pdfBranding);
        lastBlobUrlRef.current = generated.blobUrl;
        pdfMeta = {
          pdfFileName: generated.fileName,
          pdfBlobUrl: generated.blobUrl,
          popupBlocked: !generated.openedInNewTab,
          pdfFailed: false,
        };
      } catch (pdfErr) {
        const reason = pdfErr instanceof Error ? pdfErr.message : 'pdf_generation_failed';
        void api.reportPdfFailure(result.certificate.id, reason).catch(() => undefined);
        pdfMeta = { popupBlocked: true, pdfFailed: true };
      }

      setLastIssued({
        ...result,
        ...pdfMeta,
      });

      // Rotate idempotency key ONLY after confirmed persistence
      idempotencyKeyRef.current = createIdempotencyKey();
      const resetForm = createInitialForm();
      setForm(resetForm);
      setSelectedMakeOption('');
      setCustomMake('');
      void loadCandidates(resetForm.issueDate);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        setSessionExpired(true);
        setError('Your session has expired or is no longer valid. Please sign in again to issue certificates.');
      } else {
        setError(
          err instanceof ApiError
            ? err.message
            : 'Certificate issuance failed. Retrying will safely reuse the same idempotency key.'
        );
      }
    } finally {
      inFlightRef.current = false;
      setSubmitting(false);
    }
  };

  const isUnhidden = form.unhideChassisEngine === true;

  return (
    <div className="bg-white border border-slate-200 rounded-xl p-6 sm:p-8">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 pb-6 border-b border-slate-200">
        <div>
          <h2 className="font-display text-xl font-bold text-[#0B1F3A]">
            Make New Scrapping Certificate
          </h2>
          <p className="text-sm text-slate-600 mt-1">
            Numbers are generated cryptographically and reserved atomically upon issuance.
          </p>
        </div>

        {/* Cryptographic Candidate Preview + Non-Consuming Refresh */}
        <div className="flex items-center gap-3 bg-slate-50 border border-slate-200 rounded-lg px-4 py-2.5">
          <div className="text-xs">
            <div className="text-slate-500">Next Available Numbers</div>
            <div className="font-mono font-semibold text-[#0B1F3A] mt-0.5 tabular-nums">
              {loadingCandidates && !candidates ? (
                <span>Generating...</span>
              ) : candidateError && !candidates ? (
                <span className="font-sans font-medium text-red-700">{candidateError}</span>
              ) : candidates ? (
                <>
                  <span>{candidates.certificateNumber}</span>
                  <span className="mx-2 text-slate-300">/</span>
                  <span className="text-[#059669]">{candidates.scrappingRegNumber}</span>
                </>
              ) : (
                <span className="font-sans font-medium text-amber-800">Numbers unavailable</span>
              )}
            </div>
            {candidateError && candidates && (
              <p className="text-[11px] font-sans text-red-700 mt-0.5">{candidateError}</p>
            )}
          </div>
          {candidateError ? (
            <button
              type="button"
              onClick={() => void loadCandidates(form.issueDate)}
              disabled={loadingCandidates || submitting}
              className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-md border border-red-300 bg-white hover:bg-red-50 text-xs font-semibold text-red-700 transition-colors disabled:opacity-50 cursor-pointer whitespace-nowrap"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loadingCandidates ? 'animate-spin' : ''}`} />
              Retry
            </button>
          ) : (
            <button
              type="button"
              onClick={() => void loadCandidates(form.issueDate)}
              disabled={loadingCandidates || submitting}
              title="Generate new available random candidates without consuming them"
              className="p-2 rounded-md border border-slate-300 bg-white hover:bg-slate-100 text-slate-700 transition-colors disabled:opacity-50 cursor-pointer"
            >
              <RefreshCw className={`w-4 h-4 ${loadingCandidates ? 'animate-spin' : ''}`} />
            </button>
          )}
        </div>
      </div>

      {/* Confirmed Issuance Banner with Automatic PDF Status & Fallbacks */}
      {lastIssued && (
        <div className="mt-6 p-4 rounded-lg bg-emerald-50 border border-emerald-200 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-start gap-3">
            <CheckCircle2 className="w-5 h-5 text-[#059669] shrink-0 mt-0.5" />
            <div className="text-sm">
              <p className="font-semibold text-emerald-950">
                {lastIssued.pdfFailed
                  ? 'Certificate Saved — Click Download PDF to Retry PDF Export'
                  : `Certificate Issued & PDF Generated (${lastIssued.pdfFileName ?? 'Official PDF'})`}
              </p>
              <p className="text-emerald-900 mt-0.5 font-mono text-xs tabular-nums">
                {lastIssued.certificate.certificateNumber} · {lastIssued.certificate.scrappingRegNumber} ·{' '}
                {lastIssued.certificate.ownerName} ({lastIssued.certificate.vehicleRegNumber}) · Committed in{' '}
                {lastIssued.persistenceMs}ms
              </p>
              {lastIssued.pdfFailed ? (
                <p className="text-xs text-amber-800 mt-1">
                  The certificate is safely stored in Firestore, but automatic PDF export encountered an error. Use{' '}
                  <strong>Download PDF</strong> or <strong>Preview &amp; QR</strong> below.
                </p>
              ) : lastIssued.popupBlocked ? (
                <p className="text-xs text-amber-800 mt-1">
                  Your browser blocked automatic new-tab opening. Use <strong>Open PDF</strong> or{' '}
                  <strong>Download PDF</strong> below.
                </p>
              ) : null}
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2 shrink-0">
            {lastIssued.pdfBlobUrl && (
              <a
                href={lastIssued.pdfBlobUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-[#0B1F3A] hover:bg-[#132f57] text-white transition-colors whitespace-nowrap"
              >
                <ExternalLink className="w-3.5 h-3.5" />
                Open PDF
              </a>
            )}
            <button
              type="button"
              onClick={() => void downloadCertificatePdf(lastIssued.certificate, pdfBranding)}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-[#059669] hover:bg-[#047857] text-white transition-colors cursor-pointer whitespace-nowrap"
            >
              <Download className="w-3.5 h-3.5" />
              Download PDF
            </button>
            <button
              type="button"
              onClick={() => onPreviewCertificate(lastIssued.certificate)}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-white border border-emerald-300 text-emerald-900 hover:bg-emerald-100 transition-colors cursor-pointer whitespace-nowrap"
            >
              <Eye className="w-3.5 h-3.5" />
              Preview &amp; QR
            </button>
          </div>
        </div>
      )}

      {(error || sessionExpired) && (
        <div
          role="alert"
          className="mt-6 p-4 rounded-lg bg-red-50 border border-red-200 text-red-800 text-sm flex flex-col sm:flex-row sm:items-center justify-between gap-3"
        >
          <div className="flex items-start gap-2.5">
            <AlertCircle className="w-4 h-4 shrink-0 mt-0.5 text-red-600" />
            <span>
              {error ??
                'Your Maker session has expired or is invalid. Please sign in again to continue.'}
            </span>
          </div>
          {sessionExpired && onSessionExpired && (
            <button
              type="button"
              onClick={onSessionExpired}
              className="inline-flex items-center justify-center px-3.5 py-1.5 rounded-lg bg-red-700 hover:bg-red-800 text-white text-xs font-semibold transition-colors cursor-pointer whitespace-nowrap shrink-0"
            >
              Sign In Again
            </button>
          )}
        </div>
      )}

      <form onSubmit={handleSubmit} className="mt-6 space-y-8">
        {/* Section 1: Issuance & Handover Dates */}
        <div>
          <h3 className="text-sm font-bold text-[#0B1F3A] mb-4">
            01. Certificate Issuance Dates
          </h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-slate-700 mb-1.5">
                Issue Date <span className="text-red-600">*</span>
              </label>
              <input
                type="date"
                required
                value={form.issueDate}
                onChange={(e) => updateField('issueDate', e.target.value)}
                className="w-full px-3 py-2 rounded-lg border border-slate-300 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-[#059669]"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-700 mb-1.5">
                Vehicle Handover Date <span className="text-red-600">*</span>
              </label>
              <input
                type="date"
                required
                value={form.handoverDate}
                onChange={(e) => updateField('handoverDate', e.target.value)}
                className="w-full px-3 py-2 rounded-lg border border-slate-300 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-[#059669]"
              />
            </div>
          </div>
        </div>

        {/* Section 2: Owner Particulars */}
        <div className="pt-6 border-t border-slate-200">
          <h3 className="text-sm font-bold text-[#0B1F3A] mb-4">
            02. Registered Vehicle Owner Particulars
          </h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            <div>
              <label className="block text-xs font-medium text-slate-700 mb-1.5">
                Owner Full Name <span className="text-red-600">*</span>
              </label>
              <input
                type="text"
                required
                minLength={2}
                value={form.ownerName}
                onChange={(e) => updateField('ownerName', e.target.value)}
                placeholder="As per RC / ID proof"
                className="w-full px-3 py-2 rounded-lg border border-slate-300 text-sm focus:outline-none focus:ring-2 focus:ring-[#059669]"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-700 mb-1.5">
                ID Proof Type <span className="text-slate-400 font-normal">(Optional)</span>
              </label>
              <select
                value={form.idProofType ?? ''}
                onChange={(e) => updateField('idProofType', e.target.value as IdProofType)}
                className="w-full px-3 py-2 rounded-lg border border-slate-300 text-sm bg-white focus:outline-none focus:ring-2 focus:ring-[#059669]"
              >
                {ID_PROOF_OPTIONS.map((opt) => (
                  <option key={opt.value || 'none'} value={opt.value}>
                    {opt.label}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-700 mb-1.5">
                ID Proof Number <span className="text-slate-400 font-normal">(Optional)</span>
              </label>
              <input
                type="text"
                value={form.idProofNumber ?? ''}
                onChange={(e) => updateField('idProofNumber', e.target.value.toUpperCase())}
                placeholder="Optional — never shown publicly"
                className="w-full px-3 py-2 rounded-lg border border-slate-300 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-[#059669]"
              />
            </div>

            <div className="sm:col-span-2 lg:col-span-3">
              <label className="block text-xs font-medium text-slate-700 mb-1.5">
                Residential Address <span className="text-slate-400 font-normal">(Optional)</span>
              </label>
              <input
                type="text"
                value={form.ownerAddress ?? ''}
                onChange={(e) => updateField('ownerAddress', e.target.value)}
                placeholder="Optional — House/Flat No., Street, City, State, PIN"
                className="w-full px-3 py-2 rounded-lg border border-slate-300 text-sm focus:outline-none focus:ring-2 focus:ring-[#059669]"
              />
            </div>
          </div>
        </div>

        {/* Section 3: Vehicle Particulars */}
        <div className="pt-6 border-t border-slate-200">
          <h3 className="text-sm font-bold text-[#0B1F3A] mb-4">
            03. Vehicle Technical Particulars
          </h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            <div>
              <label className="block text-xs font-medium text-slate-700 mb-1.5">
                RC Number (Vehicle Number) <span className="text-red-600">*</span>
              </label>
              <input
                type="text"
                required
                minLength={4}
                value={form.vehicleRegNumber}
                onChange={(e) => updateField('vehicleRegNumber', e.target.value.toUpperCase())}
                placeholder="e.g. DL01AB1234"
                className="w-full px-3 py-2 rounded-lg border border-slate-300 text-sm font-mono uppercase focus:outline-none focus:ring-2 focus:ring-[#059669]"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-700 mb-1.5">
                Make / Manufacturer <span className="text-red-600">*</span>
              </label>
              <select
                required
                value={selectedMakeOption}
                onChange={(e) => handleMakeDropdownChange(e.target.value)}
                className="w-full px-3 py-2 rounded-lg border border-slate-300 text-sm bg-white focus:outline-none focus:ring-2 focus:ring-[#059669]"
              >
                <option value="">-- Select Manufacturer (Bikes, Scooty, Cars...) --</option>
                {VEHICLE_MANUFACTURER_GROUPS.map((group) => (
                  <optgroup key={group.category} label={group.category}>
                    {group.brands.map((brand) => (
                      <option key={brand} value={brand}>
                        {brand}
                      </option>
                    ))}
                  </optgroup>
                ))}
                <optgroup label="Other">
                  <option value={OTHER_MANUFACTURER_VALUE}>Other (Type Manually)</option>
                </optgroup>
              </select>
              {selectedMakeOption === OTHER_MANUFACTURER_VALUE && (
                <input
                  type="text"
                  required
                  minLength={2}
                  value={customMake}
                  onChange={(e) => {
                    setCustomMake(e.target.value);
                    updateField('make', e.target.value);
                  }}
                  placeholder="Enter custom manufacturer name"
                  className="mt-2 w-full px-3 py-2 rounded-lg border border-slate-300 text-sm focus:outline-none focus:ring-2 focus:ring-[#059669]"
                />
              )}
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-700 mb-1.5">
                Model / Variant <span className="text-red-600">*</span>
              </label>
              <input
                type="text"
                required
                value={form.model}
                onChange={(e) => updateField('model', e.target.value)}
                placeholder="e.g. Activa 6G / Splendor / Swift"
                className="w-full px-3 py-2 rounded-lg border border-slate-300 text-sm focus:outline-none focus:ring-2 focus:ring-[#059669]"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-700 mb-1.5">
                Year of Manufacture <span className="text-red-600">*</span>
              </label>
              <input
                type="number"
                required
                min={1950}
                max={new Date().getFullYear() + 1}
                value={form.manufactureYear}
                onChange={(e) => updateField('manufactureYear', Number(e.target.value))}
                className="w-full px-3 py-2 rounded-lg border border-slate-300 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-[#059669]"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-700 mb-1.5">
                Chassis Number (VIN) <span className="text-red-600">*</span>
              </label>
              <input
                type="text"
                required
                minLength={6}
                value={form.chassisNumber}
                onChange={(e) => updateField('chassisNumber', e.target.value.toUpperCase())}
                placeholder="Enter full Chassis Number"
                className="w-full px-3 py-2 rounded-lg border border-slate-300 text-sm font-mono uppercase focus:outline-none focus:ring-2 focus:ring-[#059669]"
              />
              {form.chassisNumber.trim().length > 0 && (
                <p className="mt-1 text-[11px] font-mono text-slate-500">
                  Certificate prints:{' '}
                  <span className="font-semibold text-[#0B1F3A]">
                    {formatChassisOrEngine(form.chassisNumber, isUnhidden)}
                  </span>
                </p>
              )}
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-700 mb-1.5">
                Engine Number <span className="text-red-600">*</span>
              </label>
              <input
                type="text"
                required
                minLength={5}
                value={form.engineNumber}
                onChange={(e) => updateField('engineNumber', e.target.value.toUpperCase())}
                placeholder="Enter full Engine Number"
                className="w-full px-3 py-2 rounded-lg border border-slate-300 text-sm font-mono uppercase focus:outline-none focus:ring-2 focus:ring-[#059669]"
              />
              {form.engineNumber.trim().length > 0 && (
                <p className="mt-1 text-[11px] font-mono text-slate-500">
                  Certificate prints:{' '}
                  <span className="font-semibold text-[#0B1F3A]">
                    {formatChassisOrEngine(form.engineNumber, isUnhidden)}
                  </span>
                </p>
              )}
            </div>

            {/* Chassis & Engine Unhide Toggle */}
            <div className="sm:col-span-2 lg:col-span-3">
              <label className="flex items-start gap-3 p-3.5 rounded-lg border border-slate-200 bg-slate-50 cursor-pointer hover:bg-slate-100/70 transition-colors">
                <input
                  type="checkbox"
                  checked={isUnhidden}
                  onChange={(e) => updateField('unhideChassisEngine', e.target.checked)}
                  className="mt-0.5 h-4 w-4 rounded border-slate-300 text-[#059669] focus:ring-[#059669] cursor-pointer"
                />
                <div className="text-xs">
                  <div className="font-semibold text-[#0B1F3A] flex items-center gap-1.5">
                    {isUnhidden ? (
                      <Eye className="w-3.5 h-3.5 text-[#059669]" />
                    ) : (
                      <EyeOff className="w-3.5 h-3.5 text-slate-500" />
                    )}
                    <span>Unhide full Chassis &amp; Engine Number on Certificate &amp; PDF</span>
                  </div>
                  <p className="text-slate-600 mt-0.5">
                    Leave unticked to hide both ends as{' '}
                    <span className="font-mono font-semibold">XXXX...XX</span> (default). Tick this
                    box if you need the full unmasked Chassis &amp; Engine numbers printed.
                  </p>
                </div>
              </label>
            </div>

            <div className="sm:col-span-2 lg:col-span-3">
              <label className="block text-xs font-medium text-slate-700 mb-1.5">
                Remarks / Inspection Notes <span className="text-slate-400 font-normal">(Optional)</span>
              </label>
              <input
                type="text"
                value={form.remarks ?? ''}
                onChange={(e) => updateField('remarks', e.target.value)}
                placeholder="e.g. Physical chassis plate cut and verified, RC surrendered"
                className="w-full px-3 py-2 rounded-lg border border-slate-300 text-sm focus:outline-none focus:ring-2 focus:ring-[#059669]"
              />
            </div>
          </div>
        </div>

        {/* Form Actions */}
        <div className="pt-6 border-t border-slate-200 flex flex-col sm:flex-row items-center justify-between gap-4">
          <p className="text-xs text-slate-500">
            Issuance computes a canonical SHA-256 digest, reserves both numbers atomically, and
            prevents duplicate commits via idempotency protection.
          </p>
          <button
            type="submit"
            disabled={submitting}
            className="w-full sm:w-auto inline-flex items-center justify-center gap-2 px-6 py-2.5 rounded-lg bg-[#059669] hover:bg-[#047857] text-white font-semibold text-sm transition-colors disabled:opacity-50 whitespace-nowrap shrink-0 cursor-pointer"
          >
            <FilePlus2 className="w-4 h-4" />
            {submitting ? 'Committing Certificate...' : 'Issue Official Certificate'}
          </button>
        </div>
      </form>
    </div>
  );
};
