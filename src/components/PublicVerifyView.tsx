import React, { useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle,
  ArrowLeft,
  Check,
  ExternalLink,
  KeyRound,
  QrCode,
  Search,
  ShieldAlert,
  ShieldCheck,
  X,
} from 'lucide-react';
import type { PublicVerificationResult } from '../shared/types';
import { api } from '../lib/api';
import { generateQrDataUrl } from '../lib/pdfGenerator';

interface PublicVerifyViewProps {
  initialCertNumber?: string;
  initialToken?: string;
  onBackToPortal: () => void;
}

export const PublicVerifyView: React.FC<PublicVerifyViewProps> = ({
  initialCertNumber = '',
  initialToken = '',
  onBackToPortal,
}) => {
  const [certInput, setCertInput] = useState(initialCertNumber);
  const [tokenInput] = useState(initialToken);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<PublicVerificationResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [qrDataUrl, setQrDataUrl] = useState<string>('');
  const [showFullHash, setShowFullHash] = useState(false);

  const runVerification = async (certNumber: string, token?: string) => {
    const trimmed = certNumber.trim();
    if (!trimmed) return;
    setLoading(true);
    setError(null);
    setShowFullHash(false);
    try {
      const data = await api.verifyPublicCertificate(trimmed, token);
      setResult(data);
    } catch {
      setError('Unable to reach the verification service. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (initialCertNumber.trim()) {
      void runVerification(initialCertNumber, initialToken);
    }
  }, [initialCertNumber, initialToken]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    void runVerification(
      certInput,
      certInput.trim().toUpperCase() === initialCertNumber.trim().toUpperCase()
        ? tokenInput
        : undefined
    );
  };

  // Strictly verified ONLY when backend confirms record exists, status is ACTIVE,
  // SHA-256 canonical digest matches, and token (if supplied) matches.
  const isStrictlyVerified = Boolean(
    result && result.found && result.verified && result.integrityMatch
  );

  const canonicalVerifyUrl = useMemo(() => {
    if (!result?.found || !result.certificateNumber) return '';
    const origin = typeof window !== 'undefined' ? window.location.origin : '';
    const qs = new URLSearchParams({ certificateNumber: result.certificateNumber });
    if (
      tokenInput &&
      result.tokenMatch === true &&
      result.certificateNumber.toUpperCase() === initialCertNumber.trim().toUpperCase()
    ) {
      qs.set('token', tokenInput);
    }
    return `${origin}/verify?${qs.toString()}`;
  }, [result, tokenInput, initialCertNumber]);

  useEffect(() => {
    let active = true;
    if (!isStrictlyVerified || !canonicalVerifyUrl) {
      setQrDataUrl('');
      return;
    }
    void generateQrDataUrl(canonicalVerifyUrl).then((url) => {
      if (active) setQrDataUrl(url);
    });
    return () => {
      active = false;
    };
  }, [isStrictlyVerified, canonicalVerifyUrl]);

  const shortHash = result?.canonicalHash ? `${result.canonicalHash.slice(0, 16)}...` : '';

  return (
    <div className="min-h-screen bg-slate-50 flex flex-col">
      {/* Top Bar */}
      <header className="bg-white border-b border-slate-200 px-4 sm:px-6 py-4">
        <div className="max-w-5xl mx-auto flex items-center justify-between gap-4 sm:gap-8">
          <div className="flex items-center gap-3 whitespace-nowrap shrink-0">
            <div className="w-9 h-9 rounded-lg bg-[#0B1F3A] text-white flex items-center justify-center font-display font-bold text-sm">
              PS
            </div>
            <span className="font-display font-bold text-base sm:text-lg text-[#0B1F3A]">
              Parivahan Scrappers
            </span>
          </div>

          <span className="hidden md:inline text-sm text-slate-600 whitespace-nowrap">
            Public Certificate Verification Portal
          </span>

          <button
            type="button"
            onClick={onBackToPortal}
            className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg text-sm font-semibold text-[#0B1F3A] border border-slate-300 bg-white hover:bg-slate-50 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            <ArrowLeft className="w-4 h-4" />
            Portal Sign In
          </button>
        </div>
      </header>

      <main className="flex-1 max-w-4xl w-full mx-auto px-4 sm:px-6 py-8 sm:py-10 space-y-6">
        {/* Search Lookup Card */}
        <section className="bg-white border border-slate-200 rounded-2xl p-6 sm:p-8 shadow-xs">
          <div className="flex items-start gap-3.5">
            <div className="w-10 h-10 rounded-xl bg-emerald-50 border border-emerald-200 flex items-center justify-center shrink-0">
              <QrCode className="w-5 h-5 text-[#059669]" />
            </div>
            <div>
              <h1 className="font-display text-xl sm:text-2xl font-bold text-[#0B1F3A] tracking-tight">
                Public Certificate Verification
              </h1>
              <p className="text-sm text-slate-600 mt-1 leading-relaxed">
                Verify authenticity and SHA-256 cryptographic integrity of any Parivahan Scrappers
                vehicle scrapping certificate without signing in.
              </p>
            </div>
          </div>

          <form onSubmit={handleSubmit} className="mt-6 flex flex-col sm:flex-row gap-3">
            <div className="relative flex-1">
              <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                required
                value={certInput}
                onChange={(e) => setCertInput(e.target.value.toUpperCase())}
                placeholder="Enter Certificate Number (e.g. PS/26/R4829103)"
                className="w-full pl-10 pr-4 py-2.5 rounded-xl border border-slate-300 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-[#059669] focus:border-[#059669]"
              />
            </div>
            <button
              type="submit"
              disabled={loading}
              className="px-6 py-2.5 rounded-xl bg-[#0B1F3A] hover:bg-[#132f57] text-white font-semibold text-sm transition-colors disabled:opacity-50 whitespace-nowrap shrink-0 cursor-pointer"
            >
              {loading ? 'Verifying...' : 'Verify Certificate'}
            </button>
          </form>

          {error && (
            <div className="mt-5 p-4 rounded-xl bg-red-50 border border-red-200 text-red-800 text-sm flex items-center gap-2.5">
              <AlertTriangle className="w-4 h-4 shrink-0 text-red-600" />
              <span>{error}</span>
            </div>
          )}
        </section>

        {/* Verification Outcome Display */}
        {result && (
          <div className="space-y-6">
            {isStrictlyVerified ? (
              /* ==============================================================
                 VERIFIED SUCCESS PANEL (Rendered ONLY when backend confirms
                 existence + ACTIVE status + SHA-256 integrity match)
                 ============================================================== */
              <section
                aria-label="Verified Certificate Result"
                className="bg-white border border-emerald-200/90 rounded-2xl shadow-sm overflow-hidden"
              >
                {/* Hero Green-and-White Verification Header */}
                <div className="bg-gradient-to-b from-[#EBFDF3] via-[#F4FEF8] to-white px-6 sm:px-10 pt-9 pb-8 text-center border-b border-emerald-100">
                  {/* Large Prominent Green Circular Tick */}
                  <div className="mx-auto w-20 h-20 sm:w-24 sm:h-24 rounded-full bg-[#009A5E] ring-8 ring-emerald-100 shadow-md flex items-center justify-center">
                    <Check className="w-11 h-11 sm:w-12 sm:h-12 text-white" strokeWidth={3} />
                  </div>

                  {/* Clear Green Status Badge */}
                  <div className="mt-5 inline-flex items-center gap-1.5 px-3.5 py-1 rounded-full bg-emerald-100/90 border border-emerald-200 text-[#046C4E] text-xs font-bold tracking-wider uppercase">
                    <ShieldCheck className="w-3.5 h-3.5 text-[#009A5E]" />
                    <span>AUTHENTIC CERTIFICATE</span>
                  </div>

                  {/* Primary Verified Heading */}
                  <h2 className="mt-3.5 font-serif text-2xl sm:text-4xl font-bold text-[#0B1F3A] tracking-tight">
                    ✓ VERIFIED CERTIFICATE
                  </h2>

                  {/* Authoritative Subtitle (No Government/RTO claim) */}
                  <p className="mt-2.5 text-sm sm:text-base text-[#065F46] max-w-xl mx-auto leading-relaxed">
                    Certificate successfully verified against Parivahan Scrappers&apos; authorized
                    database.
                  </p>

                  {/* Certificate Number Highlight */}
                  <div className="mt-5 inline-flex flex-wrap items-center justify-center gap-2 px-4 py-2 rounded-xl bg-white border border-emerald-200/90 shadow-2xs text-sm">
                    <span className="text-slate-500 font-medium">Certificate No.</span>
                    <span className="font-mono font-bold text-[#0B1F3A] tracking-wide tabular-nums">
                      {result.certificateNumber}
                    </span>
                  </div>

                  {/* Clickable QR Verification Card */}
                  {canonicalVerifyUrl && (
                    <div className="mt-7 flex justify-center">
                      <a
                        href={canonicalVerifyUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="group inline-flex flex-col items-center gap-3 px-6 py-5 rounded-2xl bg-white border-2 border-dashed border-emerald-300 hover:border-[#009A5E] hover:shadow-md transition-all cursor-pointer"
                      >
                        <div className="w-36 h-36 sm:w-40 sm:h-40 rounded-lg bg-white p-1.5 flex items-center justify-center">
                          {qrDataUrl ? (
                            <img
                              src={qrDataUrl}
                              alt={`Verification QR Code for ${result.certificateNumber}`}
                              className="w-full h-full object-contain"
                            />
                          ) : (
                            <div className="w-full h-full rounded bg-slate-100 animate-pulse" />
                          )}
                        </div>
                        <span className="inline-flex items-center gap-1.5 text-xs sm:text-sm font-semibold text-[#0B1F3A] group-hover:text-[#009A5E] transition-colors">
                          <ExternalLink className="w-4 h-4 text-[#009A5E]" />
                          Click QR to Open Certificate
                        </span>
                      </a>
                    </div>
                  )}
                </div>

                {/* SHA-256 Data Integrity Verification Strip */}
                <div className="px-6 sm:px-8 pt-6 pb-2 bg-white">
                  <div className="rounded-xl bg-[#EEFCF4] border border-emerald-200 px-4 sm:px-5 py-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                    <div className="flex items-start gap-3">
                      <div className="w-9 h-9 rounded-lg bg-white border border-emerald-200 flex items-center justify-center shrink-0 mt-0.5">
                        <KeyRound className="w-4 h-4 text-[#009A5E]" />
                      </div>
                      <div>
                        <p className="text-xs sm:text-sm font-bold text-[#064E3B] tracking-wide">
                          ✓ DATA INTEGRITY VERIFIED (SHA-256)
                        </p>
                        <p className="text-xs text-[#047857] mt-0.5 leading-relaxed">
                          Cryptographic hash matched against canonical database record. Record has
                          not been altered.
                        </p>
                      </div>
                    </div>

                    <button
                      type="button"
                      onClick={() => setShowFullHash((v) => !v)}
                      title="Click to toggle full SHA-256 digest"
                      className="self-start sm:self-center px-3 py-1.5 rounded-lg bg-white border border-emerald-200 hover:border-emerald-400 font-mono text-xs font-medium text-[#065F46] transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                    >
                      HASH: {shortHash}
                    </button>
                  </div>

                  {showFullHash && result.canonicalHash && (
                    <div className="mt-2.5 px-4 py-3 rounded-lg bg-slate-50 border border-slate-200 text-[11px] font-mono text-slate-700 break-all">
                      <span className="font-semibold text-slate-500 mr-2">Full SHA-256:</span>
                      {result.canonicalHash}
                    </div>
                  )}
                </div>

                {/* Verified Certificate Summary Grid */}
                <div className="px-6 sm:px-8 py-6 bg-white">
                  <h3 className="text-sm font-bold text-[#0B1F3A] pb-3 border-b border-slate-100">
                    Verified Certificate Details
                  </h3>
                  <dl className="mt-4 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-x-8 gap-y-5 text-sm">
                    <div>
                      <dt className="text-xs font-medium text-slate-500">Certificate Number</dt>
                      <dd className="font-mono font-semibold text-[#0B1F3A] mt-0.5 tabular-nums">
                        {result.certificateNumber}
                      </dd>
                    </div>
                    <div>
                      <dt className="text-xs font-medium text-slate-500">Scrapping Reg. Number</dt>
                      <dd className="font-mono font-semibold text-[#0B1F3A] mt-0.5 tabular-nums">
                        {result.scrappingRegNumber}
                      </dd>
                    </div>
                    <div>
                      <dt className="text-xs font-medium text-slate-500">Record Status</dt>
                      <dd className="font-semibold text-[#059669] mt-0.5">
                        {result.status} · Version {result.version}
                      </dd>
                    </div>
                    <div>
                      <dt className="text-xs font-medium text-slate-500">Registered Owner Name</dt>
                      <dd className="font-semibold text-slate-900 mt-0.5">{result.ownerName}</dd>
                    </div>
                    <div>
                      <dt className="text-xs font-medium text-slate-500">
                        Vehicle Registration (RC) No.
                      </dt>
                      <dd className="font-mono font-semibold text-slate-900 mt-0.5">
                        {result.vehicleRegNumber}
                      </dd>
                    </div>
                    <div>
                      <dt className="text-xs font-medium text-slate-500">Make &amp; Model</dt>
                      <dd className="font-medium text-slate-900 mt-0.5">
                        {result.make} {result.model} ({result.manufactureYear})
                      </dd>
                    </div>
                    <div>
                      <dt className="text-xs font-medium text-slate-500">Date of Issue</dt>
                      <dd className="font-mono text-slate-900 mt-0.5 tabular-nums">
                        {result.issueDate}
                      </dd>
                    </div>
                    <div>
                      <dt className="text-xs font-medium text-slate-500">Date of Handover</dt>
                      <dd className="font-mono text-slate-900 mt-0.5 tabular-nums">
                        {result.handoverDate}
                      </dd>
                    </div>
                    <div>
                      <dt className="text-xs font-medium text-slate-500">Issuing Facility</dt>
                      <dd className="font-medium text-slate-900 mt-0.5">
                        {result.facilityName}
                      </dd>
                    </div>
                    <div>
                      <dt className="text-xs font-medium text-slate-500">
                        Chassis Number (Masked)
                      </dt>
                      <dd className="font-mono font-medium text-slate-900 mt-0.5">
                        {result.maskedChassisNumber}
                      </dd>
                    </div>
                    <div>
                      <dt className="text-xs font-medium text-slate-500">
                        Engine Number (Masked)
                      </dt>
                      <dd className="font-mono font-medium text-slate-900 mt-0.5">
                        {result.maskedEngineNumber}
                      </dd>
                    </div>
                    <div>
                      <dt className="text-xs font-medium text-slate-500">QR Token Check</dt>
                      <dd className="font-medium text-slate-700 mt-0.5">
                        {result.tokenMatch === true
                          ? 'Signed QR Token Valid'
                          : 'Verified by Certificate Number'}
                      </dd>
                    </div>
                  </dl>

                  <p className="mt-6 pt-4 border-t border-slate-100 text-xs text-slate-500 leading-relaxed">
                    Privacy Protected: Full chassis numbers, engine numbers, residential addresses,
                    and personal ID proof details are masked on public verification. Verification
                    reflects Parivahan Scrappers&apos; internal scrapping registry only.
                  </p>
                </div>
              </section>
            ) : (
              /* ==============================================================
                 INVALID / UNVERIFIED / CANCELLED RED ALERT PANEL
                 (Never shows green tick or verified status)
                 ============================================================== */
              <section
                aria-label="Invalid or Unverified Certificate Result"
                className="bg-white border border-red-200 rounded-2xl shadow-sm overflow-hidden"
              >
                <div className="bg-gradient-to-b from-red-50 via-red-50/50 to-white px-6 sm:px-10 py-9 text-center border-b border-red-100">
                  <div className="mx-auto w-20 h-20 rounded-full bg-red-600 ring-8 ring-red-100 shadow-md flex items-center justify-center">
                    {result.found && result.status === 'CANCELLED' ? (
                      <ShieldAlert className="w-10 h-10 text-white" />
                    ) : (
                      <X className="w-11 h-11 text-white" strokeWidth={3} />
                    )}
                  </div>

                  <div className="mt-5 inline-flex items-center gap-1.5 px-3.5 py-1 rounded-full bg-red-100 border border-red-200 text-red-800 text-xs font-bold tracking-wider uppercase">
                    <span>
                      {result.found && result.status === 'CANCELLED'
                        ? 'CERTIFICATE CANCELLED'
                        : 'UNVERIFIED / INVALID'}
                    </span>
                  </div>

                  <h2 className="mt-3.5 font-serif text-2xl sm:text-3xl font-bold text-red-950 tracking-tight">
                    {result.found && result.status === 'CANCELLED'
                      ? 'CERTIFICATE OFFICIALLY CANCELLED'
                      : result.found
                        ? 'VERIFICATION FAILED — INTEGRITY MISMATCH'
                        : 'INVALID / UNVERIFIED CERTIFICATE'}
                  </h2>

                  <p className="mt-2.5 text-sm sm:text-base text-red-800 max-w-xl mx-auto leading-relaxed">
                    {result.message}
                  </p>

                  {result.certificateNumber && (
                    <div className="mt-5 inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-white border border-red-200 text-sm">
                      <span className="text-slate-500 font-medium">Checked Number</span>
                      <span className="font-mono font-bold text-red-900">
                        {result.certificateNumber}
                      </span>
                    </div>
                  )}
                </div>

                {result.found && (
                  <div className="px-6 sm:px-8 py-6 space-y-4">
                    {result.status === 'CANCELLED' && result.cancelReason && (
                      <div className="p-4 rounded-xl bg-red-50 border border-red-200 text-sm text-red-900">
                        <span className="font-semibold">Cancellation Reason: </span>
                        <span>{result.cancelReason}</span>
                      </div>
                    )}

                    <div className="rounded-xl bg-red-50/70 border border-red-200 p-4 text-xs text-red-900 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                      <span className="font-semibold">
                        SHA-256 Integrity Check:{' '}
                        {result.integrityMatch ? 'Hash Matched' : 'Hash Mismatch Detected'}
                      </span>
                      <span className="font-mono">
                        Status: {result.status} · Token:{' '}
                        {result.tokenMatch === false
                          ? 'Mismatch'
                          : result.tokenMatch === true
                            ? 'Matched'
                            : 'Not Supplied'}
                      </span>
                    </div>
                  </div>
                )}
              </section>
            )}
          </div>
        )}
      </main>
    </div>
  );
};
