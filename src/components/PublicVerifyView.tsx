import React, { useEffect, useState } from 'react';
import {
  AlertTriangle,
  ArrowLeft,
  CheckCircle2,
  QrCode,
  Search,
  ShieldAlert,
  ShieldCheck,
  XCircle,
} from 'lucide-react';
import type { PublicVerificationResult } from '../shared/types';
import { api } from '../lib/api';

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

  const runVerification = async (certNumber: string, token?: string) => {
    const trimmed = certNumber.trim();
    if (!trimmed) return;
    setLoading(true);
    setError(null);
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
    void runVerification(certInput, certInput.trim().toUpperCase() === initialCertNumber.trim().toUpperCase() ? tokenInput : undefined);
  };

  return (
    <div className="min-h-screen bg-slate-50 flex flex-col">
      {/* Top Bar */}
      <header className="bg-white border-b border-slate-200 px-6 py-4">
        <div className="max-w-5xl mx-auto flex items-center justify-between gap-8">
          <div className="flex items-center gap-3 whitespace-nowrap shrink-0">
            <div className="w-9 h-9 rounded-lg bg-[#0B1F3A] text-white flex items-center justify-center font-display font-bold text-sm">
              PS
            </div>
            <span className="font-display font-bold text-lg text-[#0B1F3A]">
              Parivahan Scrappers
            </span>
          </div>

          <span className="hidden sm:inline text-sm text-slate-600 whitespace-nowrap">
            Public Certificate Verification Portal
          </span>

          <button
            type="button"
            onClick={onBackToPortal}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold text-[#0B1F3A] border border-slate-300 bg-white hover:bg-slate-50 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            <ArrowLeft className="w-4 h-4" />
            Portal Sign In
          </button>
        </div>
      </header>

      <main className="flex-1 max-w-4xl w-full mx-auto px-6 py-10">
        <div className="bg-white border border-slate-200 rounded-xl p-6 sm:p-8">
          <div className="flex items-start gap-3">
            <div className="w-10 h-10 rounded-lg bg-emerald-50 border border-emerald-200 flex items-center justify-center shrink-0">
              <QrCode className="w-5 h-5 text-[#059669]" />
            </div>
            <div>
              <h1 className="font-display text-xl sm:text-2xl font-bold text-[#0B1F3A]">
                Public Certificate Verification
              </h1>
              <p className="text-sm text-slate-600 mt-1">
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
                className="w-full pl-10 pr-4 py-2.5 rounded-lg border border-slate-300 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-[#059669] focus:border-[#059669]"
              />
            </div>
            <button
              type="submit"
              disabled={loading}
              className="px-6 py-2.5 rounded-lg bg-[#0B1F3A] hover:bg-[#132f57] text-white font-semibold text-sm transition-colors disabled:opacity-50 whitespace-nowrap shrink-0 cursor-pointer"
            >
              {loading ? 'Verifying...' : 'Verify Certificate'}
            </button>
          </form>

          {error && (
            <div className="mt-6 p-4 rounded-lg bg-red-50 border border-red-200 text-red-800 text-sm flex items-center gap-2.5">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {result && (
            <div className="mt-8 pt-6 border-t border-slate-200">
              {/* Verification Outcome Header */}
              <div
                className={`p-4 rounded-lg border flex items-start gap-3 ${
                  result.verified
                    ? 'bg-emerald-50 border-emerald-200 text-emerald-950'
                    : result.found && result.status === 'CANCELLED'
                      ? 'bg-amber-50 border-amber-200 text-amber-950'
                      : 'bg-red-50 border-red-200 text-red-950'
                }`}
              >
                {result.verified ? (
                  <ShieldCheck className="w-6 h-6 text-[#059669] shrink-0 mt-0.5" />
                ) : result.found && result.status === 'CANCELLED' ? (
                  <ShieldAlert className="w-6 h-6 text-amber-600 shrink-0 mt-0.5" />
                ) : (
                  <XCircle className="w-6 h-6 text-red-600 shrink-0 mt-0.5" />
                )}
                <div>
                  <p className="font-display font-bold text-base">
                    {result.verified
                      ? 'Certificate Verified Authentic'
                      : result.found && result.status === 'CANCELLED'
                        ? 'Certificate Officially Cancelled'
                        : result.found
                          ? 'Verification Integrity Warning'
                          : 'Certificate Record Not Found'}
                  </p>
                  <p className="text-sm mt-0.5 opacity-90">{result.message}</p>
                </div>
              </div>

              {result.found && (
                <>
                  <div className="mt-6 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-x-8 gap-y-5 text-sm">
                    <div>
                      <p className="text-xs font-medium text-slate-500">Certificate Number</p>
                      <p className="font-mono font-semibold text-[#0B1F3A] mt-0.5">
                        {result.certificateNumber}
                      </p>
                    </div>
                    <div>
                      <p className="text-xs font-medium text-slate-500">Scrapping Reg. Number</p>
                      <p className="font-mono font-semibold text-[#0B1F3A] mt-0.5">
                        {result.scrappingRegNumber}
                      </p>
                    </div>
                    <div>
                      <p className="text-xs font-medium text-slate-500">Certificate Status</p>
                      <p
                        className={`font-semibold mt-0.5 ${
                          result.status === 'ACTIVE'
                            ? 'text-[#059669]'
                            : 'text-red-700'
                        }`}
                      >
                        {result.status} · Version {result.version}
                      </p>
                    </div>
                    <div>
                      <p className="text-xs font-medium text-slate-500">Registered Owner Name</p>
                      <p className="font-semibold text-slate-900 mt-0.5">{result.ownerName}</p>
                    </div>
                    <div>
                      <p className="text-xs font-medium text-slate-500">RC Number (Vehicle No.)</p>
                      <p className="font-mono font-semibold text-slate-900 mt-0.5">
                        {result.vehicleRegNumber}
                      </p>
                    </div>
                    <div>
                      <p className="text-xs font-medium text-slate-500">Make &amp; Model</p>
                      <p className="font-medium text-slate-900 mt-0.5">
                        {result.make} {result.model} ({result.manufactureYear})
                      </p>
                    </div>
                    <div>
                      <p className="text-xs font-medium text-slate-500">Issue Date</p>
                      <p className="font-mono text-slate-900 mt-0.5">{result.issueDate}</p>
                    </div>
                    <div>
                      <p className="text-xs font-medium text-slate-500">Vehicle Handover Date</p>
                      <p className="font-mono text-slate-900 mt-0.5">{result.handoverDate}</p>
                    </div>
                    <div>
                      <p className="text-xs font-medium text-slate-500">Issuing Facility</p>
                      <p className="font-medium text-slate-900 mt-0.5">
                        {result.facilityName} ({result.facilityRvsfCode})
                      </p>
                    </div>
                    <div>
                      <p className="text-xs font-medium text-slate-500">
                        Chassis Number (Masked)
                      </p>
                      <p className="font-mono font-medium text-slate-900 mt-0.5">
                        {result.maskedChassisNumber}
                      </p>
                    </div>
                    <div>
                      <p className="text-xs font-medium text-slate-500">
                        Engine Number (Masked)
                      </p>
                      <p className="font-mono font-medium text-slate-900 mt-0.5">
                        {result.maskedEngineNumber}
                      </p>
                    </div>
                  </div>

                  {result.status === 'CANCELLED' && result.cancelReason && (
                    <div className="mt-5 p-4 rounded-lg bg-amber-50 border border-amber-200 text-sm text-amber-900">
                      <span className="font-semibold">Cancellation Reason: </span>
                      <span>{result.cancelReason}</span>
                    </div>
                  )}

                  {/* Cryptographic Integrity Box */}
                  <div className="mt-6 pt-5 border-t border-slate-200">
                    <h2 className="text-sm font-semibold text-[#0B1F3A] mb-3">
                      Cryptographic Integrity Verification
                    </h2>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                      <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200">
                        <div className="flex items-center justify-between">
                          <span className="font-medium text-slate-600">
                            Canonical SHA-256 Digest
                          </span>
                          <span
                            className={`inline-flex items-center gap-1 font-semibold ${
                              result.integrityMatch ? 'text-[#059669]' : 'text-red-700'
                            }`}
                          >
                            <CheckCircle2 className="w-3.5 h-3.5" />
                            {result.integrityMatch ? 'Hash Match Confirmed' : 'Hash Mismatch'}
                          </span>
                        </div>
                        <p className="font-mono text-[11px] text-slate-700 break-all mt-2">
                          {result.canonicalHash}
                        </p>
                      </div>

                      <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200">
                        <div className="flex items-center justify-between">
                          <span className="font-medium text-slate-600">QR Token Verification</span>
                          <span
                            className={`font-semibold ${
                              result.tokenMatch === true
                                ? 'text-[#059669]'
                                : result.tokenMatch === false
                                  ? 'text-red-700'
                                  : 'text-slate-600'
                            }`}
                          >
                            {result.tokenMatch === true
                              ? 'Signed QR Token Valid'
                              : result.tokenMatch === false
                                ? 'QR Token Mismatch'
                                : 'Manual Number Lookup'}
                          </span>
                        </div>
                        <p className="text-slate-500 mt-2">
                          Privacy Protected: Full chassis, engine, contact details, and ID proof
                          numbers are never exposed on public verification.
                        </p>
                      </div>
                    </div>
                  </div>
                </>
              )}
            </div>
          )}
        </div>
      </main>
    </div>
  );
};
