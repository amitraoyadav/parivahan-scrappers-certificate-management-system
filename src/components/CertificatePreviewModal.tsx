import React, { useEffect, useState } from 'react';
import { Check, Copy, Download, ExternalLink, Eye, EyeOff, X } from 'lucide-react';
import type { CertificateRecord } from '../shared/types';
import { formatChassisOrEngine } from '../shared/vehicleData';
import {
  buildVerificationUrl,
  downloadCertificatePdf,
  generateQrDataUrl,
  type PdfBrandingOptions,
} from '../lib/pdfGenerator';

interface CertificatePreviewModalProps {
  certificate: CertificateRecord | null;
  onClose: () => void;
  onOpenPublicVerify: (cert: CertificateRecord) => void;
  pdfBranding?: PdfBrandingOptions;
}

export const CertificatePreviewModal: React.FC<CertificatePreviewModalProps> = ({
  certificate,
  onClose,
  onOpenPublicVerify,
  pdfBranding,
}) => {
  const [qrDataUrl, setQrDataUrl] = useState<string>('');
  const [copied, setCopied] = useState(false);
  const [unhideChassisEngine, setUnhideChassisEngine] = useState(false);

  useEffect(() => {
    if (!certificate) return;
    setUnhideChassisEngine(certificate.unhideChassisEngine === true);
    let active = true;
    const url = buildVerificationUrl(certificate, pdfBranding?.customDomain);
    void generateQrDataUrl(url).then((dataUrl) => {
      if (active) setQrDataUrl(dataUrl);
    });
    return () => {
      active = false;
    };
  }, [certificate, pdfBranding?.customDomain]);

  if (!certificate) return null;

  const verifyUrl = buildVerificationUrl(certificate, pdfBranding?.customDomain);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(verifyUrl);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // ignore clipboard denial in restricted iframe
    }
  };

  const displayChassis = formatChassisOrEngine(certificate.chassisNumber, unhideChassisEngine);
  const displayEngine = formatChassisOrEngine(certificate.engineNumber, unhideChassisEngine);
  const idProofDisplay = certificate.idProofNumber
    ? `${certificate.idProofType ? `${certificate.idProofType} · ` : ''}${certificate.idProofNumber}`
    : 'Not Provided';

  return (
    <div
      className="fixed inset-0 z-50 bg-slate-900/60 flex items-center justify-center p-4 overflow-y-auto"
      role="dialog"
      aria-modal="true"
    >
      <div className="bg-white rounded-xl border border-slate-200 w-full max-w-4xl max-h-[92vh] flex flex-col overflow-hidden shadow-xl">
        {/* Modal Header */}
        <div className="px-6 py-4 border-b border-slate-200 flex flex-wrap items-center justify-between gap-4 bg-slate-50">
          <div>
            <h3 className="font-display font-bold text-base text-[#0B1F3A]">
              Certificate Preview — {certificate.certificateNumber}
            </h3>
            <p className="text-xs text-slate-500 font-mono">
              {certificate.scrappingRegNumber} · Version {certificate.version} · {certificate.status}
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <label className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-300 bg-white text-xs font-semibold text-slate-700 cursor-pointer whitespace-nowrap select-none">
              <input
                type="checkbox"
                checked={unhideChassisEngine}
                onChange={(e) => setUnhideChassisEngine(e.target.checked)}
                className="h-3.5 w-3.5 rounded border-slate-300 text-[#059669] focus:ring-[#059669] cursor-pointer"
              />
              {unhideChassisEngine ? (
                <Eye className="w-3.5 h-3.5 text-[#059669]" />
              ) : (
                <EyeOff className="w-3.5 h-3.5 text-slate-500" />
              )}
              <span>Unhide Chassis/Engine</span>
            </label>
            <button
              type="button"
              onClick={handleCopy}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-300 bg-white hover:bg-slate-100 text-xs font-semibold text-slate-700 cursor-pointer whitespace-nowrap"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-[#059669]" /> : <Copy className="w-3.5 h-3.5" />}
              {copied ? 'Copied Link' : 'Copy QR URL'}
            </button>
            <button
              type="button"
              onClick={() => onOpenPublicVerify(certificate)}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-300 bg-white hover:bg-slate-100 text-xs font-semibold text-slate-700 cursor-pointer whitespace-nowrap"
            >
              <ExternalLink className="w-3.5 h-3.5" />
              Public Verify
            </button>
            <button
              type="button"
              onClick={() =>
                void downloadCertificatePdf(certificate, {
                  ...pdfBranding,
                  unhideChassisEngine,
                })
              }
              className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-[#059669] hover:bg-[#047857] text-xs font-semibold text-white cursor-pointer whitespace-nowrap"
            >
              <Download className="w-3.5 h-3.5" />
              Download Official PDF
            </button>
            <button
              type="button"
              onClick={onClose}
              aria-label="Close preview"
              className="p-1.5 rounded-lg text-slate-500 hover:bg-slate-200 cursor-pointer"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Institutional Document Body */}
        <div className="p-6 overflow-y-auto bg-slate-100">
          <div className="bg-white border-2 border-[#0B1F3A] p-6 sm:p-8 relative max-w-3xl mx-auto">
            {certificate.status === 'CANCELLED' && (
              <div className="pointer-events-none select-none absolute inset-0 flex items-center justify-center">
                <span className="text-5xl font-display font-extrabold text-red-600/20 -rotate-24 tracking-widest border-4 border-red-600/20 px-6 py-2">
                  CANCELLED
                </span>
              </div>
            )}

            {/* Header */}
            <div className="bg-[#0B1F3A] text-white px-6 py-5 text-center border-b-4 border-[#059669]">
              <h4 className="font-display text-xl font-extrabold tracking-wide">
                PARIVAHAN SCRAPPERS
              </h4>
              <p className="text-xs font-semibold text-emerald-300 tracking-wider mt-1">
                CERTIFICATE OF VEHICLE SCRAPPING (RVSF)
              </p>
              <p className="text-xs text-slate-300 mt-1.5">
                {certificate.facilityName} · RVSF Code: {certificate.facilityRvsfCode}
              </p>
            </div>

            {/* Key Strip */}
            <div className="grid grid-cols-2 sm:grid-cols-4 border border-slate-200 bg-slate-50 mt-5 text-xs divide-y sm:divide-y-0 sm:divide-x divide-slate-200">
              <div className="p-3">
                <div className="text-slate-500 font-medium">Certificate No.</div>
                <div className="font-mono font-bold text-[#0B1F3A] mt-0.5">
                  {certificate.certificateNumber}
                </div>
              </div>
              <div className="p-3">
                <div className="text-slate-500 font-medium">Scrapping Reg. No.</div>
                <div className="font-mono font-bold text-[#0B1F3A] mt-0.5">
                  {certificate.scrappingRegNumber}
                </div>
              </div>
              <div className="p-3">
                <div className="text-slate-500 font-medium">Issue Date</div>
                <div className="font-mono font-bold text-slate-900 mt-0.5">
                  {certificate.issueDate}
                </div>
              </div>
              <div className="p-3">
                <div className="text-slate-500 font-medium">Status</div>
                <div
                  className={`font-mono font-bold mt-0.5 ${
                    certificate.status === 'ACTIVE' ? 'text-[#059669]' : 'text-red-700'
                  }`}
                >
                  {certificate.status} (v{certificate.version})
                </div>
              </div>
            </div>

            {/* Owner Section */}
            <div className="mt-5">
              <div className="bg-[#0B1F3A] text-white text-xs font-bold px-3.5 py-2">
                1. Registered Vehicle Owner Particulars
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 border-x border-b border-slate-200 text-xs">
                <div className="p-3 border-b border-slate-200 sm:border-r">
                  <span className="text-slate-500 block">Owner Full Name</span>
                  <span className="font-semibold text-slate-900">{certificate.ownerName}</span>
                </div>
                <div className="p-3 border-b border-slate-200">
                  <span className="text-slate-500 block">Vehicle Handover Date</span>
                  <span className="font-mono font-medium text-slate-900">
                    {certificate.handoverDate}
                  </span>
                </div>
                <div className="p-3 border-b sm:border-b-0 border-slate-200 sm:border-r">
                  <span className="text-slate-500 block">ID Proof (Optional)</span>
                  <span className="font-mono font-medium text-slate-900">{idProofDisplay}</span>
                </div>
                <div className="p-3">
                  <span className="text-slate-500 block">Residential Address (Optional)</span>
                  <span className="font-medium text-slate-900">
                    {certificate.ownerAddress || 'Not Provided'}
                  </span>
                </div>
              </div>
            </div>

            {/* Vehicle Section */}
            <div className="mt-5">
              <div className="bg-[#0B1F3A] text-white text-xs font-bold px-3.5 py-2">
                2. Scrapped Vehicle Particulars
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 border-x border-b border-slate-200 text-xs">
                <div className="p-3 border-b border-slate-200 sm:border-r">
                  <span className="text-slate-500 block">RC Number (Vehicle No.)</span>
                  <span className="font-mono font-bold text-[#0B1F3A]">
                    {certificate.vehicleRegNumber}
                  </span>
                </div>
                <div className="p-3 border-b border-slate-200">
                  <span className="text-slate-500 block">Registering Authority (RTO)</span>
                  <span className="font-medium text-slate-900">{certificate.rtoAuthority}</span>
                </div>
                <div className="p-3 border-b border-slate-200 sm:border-r">
                  <span className="text-slate-500 block">Make / Manufacturer</span>
                  <span className="font-medium text-slate-900">{certificate.make}</span>
                </div>
                <div className="p-3 border-b border-slate-200">
                  <span className="text-slate-500 block">Model &amp; Year</span>
                  <span className="font-medium text-slate-900">
                    {certificate.model} ({certificate.manufactureYear})
                  </span>
                </div>
                <div className="p-3 border-b sm:border-b-0 border-slate-200 sm:border-r">
                  <span className="text-slate-500 block">
                    Chassis Number (VIN){' '}
                    <span className="text-[10px] text-slate-400">
                      {unhideChassisEngine ? '(Full)' : '(Hidden)'}
                    </span>
                  </span>
                  <span className="font-mono font-medium text-slate-900">{displayChassis}</span>
                </div>
                <div className="p-3">
                  <span className="text-slate-500 block">
                    Engine Number{' '}
                    <span className="text-[10px] text-slate-400">
                      {unhideChassisEngine ? '(Full)' : '(Hidden)'}
                    </span>
                  </span>
                  <span className="font-mono font-medium text-slate-900">{displayEngine}</span>
                </div>
              </div>
            </div>

            {/* QR & Cryptographic Digest Footer */}
            <div className="mt-5 p-4 border border-slate-200 rounded-lg flex flex-col sm:flex-row items-center gap-5 bg-slate-50">
              {qrDataUrl && (
                <img
                  src={qrDataUrl}
                  alt={`QR Code for ${certificate.certificateNumber}`}
                  className="w-28 h-28 bg-white p-1.5 border border-slate-200 rounded shrink-0"
                />
              )}
              <div className="flex-1 text-xs min-w-0">
                <p className="font-bold text-[#0B1F3A]">
                  Public QR &amp; Canonical SHA-256 Integrity Digest
                </p>
                <p className="text-slate-600 mt-1">
                  Scan QR code to confirm authenticity on the live public verification route without
                  logging in.
                </p>
                <p className="font-mono text-[11px] text-slate-700 break-all mt-2 bg-white border border-slate-200 rounded px-2.5 py-1.5">
                  {certificate.canonicalHash}
                </p>
              </div>
            </div>

            {certificate.versionHistory && certificate.versionHistory.length > 0 && (
              <div className="mt-4 p-3 rounded-lg bg-slate-50 border border-slate-200 text-xs text-slate-600">
                <span className="font-semibold text-[#0B1F3A]">Version History Preserved: </span>
                <span>
                  {certificate.versionHistory.length} prior revision(s) archived with original
                  canonical hashes in audit records.
                </span>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
