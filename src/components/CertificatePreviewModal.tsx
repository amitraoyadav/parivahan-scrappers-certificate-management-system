import React, { useEffect, useState } from 'react';
import { Check, Copy, Download, ExternalLink, Eye, EyeOff, X } from 'lucide-react';
import type { CertificateRecord } from '../shared/types';
import { formatChassisOrEngine } from '../shared/vehicleData';
import {
  COMPANY_ADDRESS_LINE,
  COMPANY_HEADER_NAME,
  COMPANY_PHONE_LINE,
  COMPANY_SUBTITLE,
  COMPANY_WEBSITE_LINE,
  buildVerificationUrl,
  downloadCertificatePdf,
  formatDisplayDate,
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
    ? `${certificate.idProofType ? `${certificate.idProofType}: ` : ''}${certificate.idProofNumber}`
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
            <h3 className="font-display font-bold text-base text-[#0D2847]">
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
                <EyeOff className="w-3.5 w-3.5 text-slate-500" />
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

        {/* Exact Official A4 Certificate Visual Preview */}
        <div className="p-4 sm:p-6 overflow-y-auto bg-slate-200/70">
          <div className="bg-white mx-auto max-w-[780px] p-3 shadow-md">
            {/* Double-Line Navy Outer Border */}
            <div className="border-[2.5px] border-[#0D2847] p-[4px]">
              <div className="border border-[#0D2847] px-5 sm:px-7 py-5 relative overflow-hidden bg-white">
                {/* Subtle Circular Watermark */}
                <svg
                  viewBox="0 0 400 400"
                  aria-hidden="true"
                  className="pointer-events-none select-none absolute left-1/2 top-[48%] -translate-x-1/2 -translate-y-1/2 w-[380px] h-[380px] opacity-30"
                >
                  <defs>
                    <path id="wmTopArc" d="M 55,200 A 145,145 0 1,1 345,200" />
                    <path id="wmBottomArc" d="M 345,200 A 145,145 0 1,1 55,200" />
                  </defs>
                  <circle cx="200" cy="200" r="192" fill="none" stroke="#94A3B8" strokeWidth="3" />
                  <circle
                    cx="200"
                    cy="200"
                    r="183"
                    fill="none"
                    stroke="#94A3B8"
                    strokeWidth="1.6"
                    strokeDasharray="7 5"
                  />
                  <circle cx="200" cy="200" r="175" fill="none" stroke="#94A3B8" strokeWidth="1.2" />
                  <circle cx="200" cy="200" r="128" fill="none" stroke="#94A3B8" strokeWidth="1" />
                  <text fill="#94A3B8" fontSize="22" fontWeight="700" fontFamily="Georgia, serif" letterSpacing="4">
                    <textPath href="#wmTopArc" startOffset="50%" textAnchor="middle">
                      PARIVAHAN SCRAPPERS
                    </textPath>
                  </text>
                  <text fill="#94A3B8" fontSize="14" fontWeight="700" fontFamily="Georgia, serif" letterSpacing="2">
                    <textPath href="#wmBottomArc" startOffset="50%" textAnchor="middle">
                      RESPONSIBLE RECYCLING • GREENER INDIA
                    </textPath>
                  </text>
                </svg>

                {/* Cancelled Watermark */}
                {certificate.status === 'CANCELLED' && (
                  <div className="pointer-events-none select-none absolute inset-0 z-20 flex items-center justify-center">
                    <span className="text-5xl font-bold text-red-600/25 -rotate-24 tracking-widest border-4 border-red-600/25 px-6 py-2">
                      CANCELLED
                    </span>
                  </div>
                )}

                <div className="relative z-10">
                  {/* Top Header */}
                  <div className="flex flex-col sm:flex-row sm:items-stretch justify-between gap-4 pb-3 border-b-2 border-[#0D2847]">
                    <div>
                      <h4 className="font-serif font-bold text-2xl sm:text-[28px] leading-tight text-[#0D2847] tracking-tight">
                        {COMPANY_HEADER_NAME}
                      </h4>
                      <p className="font-serif font-bold text-sm text-[#1D293D] mt-0.5">
                        {COMPANY_SUBTITLE}
                      </p>
                      <div className="mt-2 space-y-1 text-xs text-[#1D293D]">
                        <div className="flex items-center gap-2">
                          <span className="inline-block w-3.5 text-center text-[#0D2847]">📍</span>
                          <span>{COMPANY_ADDRESS_LINE}</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="inline-block w-3.5 text-center text-[#0D2847]">📞</span>
                          <span>{COMPANY_PHONE_LINE}</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="inline-block w-3.5 text-center text-[#0D2847]">🌐</span>
                          <span className="text-[#0D2847]">{COMPANY_WEBSITE_LINE}</span>
                        </div>
                      </div>
                    </div>

                    <div className="sm:border-l sm:border-[#0D2847] sm:pl-5 flex items-center gap-3 shrink-0 self-center">
                      <svg viewBox="0 0 36 56" className="w-7 h-11 shrink-0" aria-hidden="true">
                        <path
                          d="M18 3 C29 14, 32 34, 18 49 C4 34, 7 14, 18 3 Z"
                          fill="#006045"
                        />
                        <line x1="18" y1="11" x2="18" y2="46" stroke="#FFFFFF" strokeWidth="1.6" />
                        <line x1="18" y1="48" x2="18" y2="54" stroke="#006045" strokeWidth="2.2" />
                      </svg>
                      <div className="font-serif font-bold text-sm leading-snug">
                        <div className="text-[#0D2847]">Responsible</div>
                        <div className="text-[#0D2847]">Recycling</div>
                        <div className="text-[#006045]">Greener India</div>
                      </div>
                    </div>
                  </div>

                  {/* Metadata Row */}
                  <div className="flex flex-wrap items-center justify-between gap-2 pt-2.5 text-xs sm:text-sm font-serif font-bold text-[#0D2847]">
                    <div>Certificate No. : {certificate.certificateNumber}</div>
                    <div>Date of Issue : {formatDisplayDate(certificate.issueDate)}</div>
                  </div>

                  {/* Centered Title & Sustainability Banner */}
                  <div className="text-center mt-4">
                    <h2 className="font-serif font-bold text-xl sm:text-2xl tracking-wide text-[#0D2847]">
                      VEHICLE SCRAPPING CERTIFICATE
                    </h2>
                    <p className="text-[10px] tracking-[0.16em] text-[#1E3A5F] uppercase mt-1">
                      ISSUED IN ACCORDANCE WITH APPLICABLE VEHICLE SCRAPPAGE REGULATIONS
                    </p>
                    <div className="flex justify-center my-1.5">
                      <svg viewBox="0 0 20 20" className="w-3.5 h-3.5" aria-hidden="true">
                        <path d="M16 4 C10 4, 4 9, 5 15 C11 16, 16 10, 16 4 Z" fill="#007A55" />
                      </svg>
                    </div>
                    <div className="inline-block bg-[#E1EEE6] px-6 py-1.5 text-[10px] sm:text-[11px] font-bold tracking-[0.12em] text-[#224D36] uppercase">
                      RESPONSIBLE SCRAPPING FOR A GREENER TOMORROW
                    </div>
                  </div>

                  {/* Introductory Paragraph */}
                  <p className="font-serif text-xs sm:text-[13px] leading-relaxed text-[#1D293D] mt-3.5 text-justify">
                    This is to certify that the motor vehicle mentioned below has been received by{' '}
                    <strong className="font-bold text-[#0D2847]">PARIVAHAN SCRAPPERS</strong> (A Unit
                    OF Scrapping Yard Ltd.) for dismantling and environmentally sound recycling, in
                    accordance with the provisions of the Vehicle Scrappage Policy and all applicable
                    environmental regulations.
                  </p>

                  {/* Section A: Owner Details */}
                  <div className="mt-3.5">
                    <div className="bg-[#DCE8F5] border border-[#B4CBE5] px-3 py-1 font-serif font-bold text-xs text-[#143E6D]">
                      A. OWNER DETAILS
                    </div>
                    <div className="border-x border-b border-[#B4CBE5] bg-white grid grid-cols-[34%_66%] text-xs">
                      <div className="px-3 py-1.5 font-bold text-[#1D293D] border-r border-[#B4CBE5]">
                        Owner Name
                      </div>
                      <div className="px-3 py-1.5 font-bold text-[#0D2847] uppercase break-words">
                        {certificate.ownerName}
                      </div>
                      <div className="px-3 py-1.5 font-bold text-[#1D293D] border-r border-[#B4CBE5]">
                        Address
                      </div>
                      <div className="px-3 py-1.5 text-[#334155] break-words">
                        {certificate.ownerAddress || 'Not Provided'}
                      </div>
                      <div className="px-3 py-1.5 font-bold text-[#1D293D] border-r border-[#B4CBE5]">
                        ID Proof Number
                      </div>
                      <div className="px-3 py-1.5 text-[#334155] break-words">
                        {idProofDisplay}
                      </div>
                    </div>
                  </div>

                  {/* Section B: Vehicle Details + QR Panel */}
                  <div className="mt-3">
                    <div className="bg-[#DCE8F5] border border-[#B4CBE5] px-3 py-1 font-serif font-bold text-xs text-[#143E6D]">
                      B. VEHICLE DETAILS
                    </div>
                    <div className="mt-1 border border-[#B4CBE5] grid grid-cols-1 sm:grid-cols-[76%_24%]">
                      {/* Left Vehicle Info Table */}
                      <div className="sm:border-r border-[#B4CBE5] text-xs">
                        <div className="grid grid-cols-[41%_59%] border-b border-[#B4CBE5] bg-white">
                          <div className="px-3 py-1 font-bold text-[#1D293D] border-r border-[#B4CBE5]">
                            Registration No. for Scrapping
                          </div>
                          <div className="px-3 py-1 font-bold text-[#0D2847]">
                            {certificate.scrappingRegNumber}
                          </div>
                        </div>
                        <div className="grid grid-cols-[41%_59%] border-b border-[#B4CBE5] bg-white">
                          <div className="px-3 py-1 font-bold text-[#1D293D] border-r border-[#B4CBE5]">
                            Vehicle Reg. (RC) No.
                          </div>
                          <div className="px-3 py-1 font-bold text-[#0D2847]">
                            {certificate.vehicleRegNumber}
                          </div>
                        </div>
                        <div className="grid grid-cols-[41%_59%] border-b border-[#B4CBE5] bg-white">
                          <div className="px-3 py-1 font-bold text-[#1D293D] border-r border-[#B4CBE5]">
                            Chassis No.
                          </div>
                          <div className="px-3 py-1 text-[#1D293D]">{displayChassis}</div>
                        </div>
                        <div className="grid grid-cols-[41%_59%] bg-white">
                          <div className="px-3 py-1 font-bold text-[#1D293D] border-r border-[#B4CBE5]">
                            Engine No.
                          </div>
                          <div className="px-3 py-1 text-[#1D293D]">{displayEngine}</div>
                        </div>
                        <div className="grid grid-cols-[41%_59%] bg-white">
                          <div className="px-3 py-1 font-bold text-[#1D293D] border-r border-[#B4CBE5]">
                            Maker (Bike Brand)
                          </div>
                          <div className="px-3 py-1 text-[#1D293D]">{certificate.make}</div>
                        </div>
                        <div className="grid grid-cols-[41%_59%] bg-white">
                          <div className="px-3 py-1 font-bold text-[#1D293D] border-r border-[#B4CBE5]">
                            Model
                          </div>
                          <div className="px-3 py-1 text-[#1D293D]">{certificate.model}</div>
                        </div>
                        <div className="grid grid-cols-[41%_59%] border-b border-[#B4CBE5] bg-white">
                          <div className="px-3 py-1 font-bold text-[#1D293D] border-r border-[#B4CBE5]">
                            Location
                          </div>
                          <div className="px-3 py-1 text-[#1D293D]">{certificate.rtoAuthority}</div>
                        </div>
                        <div className="grid grid-cols-[41%_59%] border-b border-[#B4CBE5] bg-white">
                          <div className="px-3 py-1 font-bold text-[#1D293D] border-r border-[#B4CBE5]">
                            Year of Manufacture
                          </div>
                          <div className="px-3 py-1 text-[#1D293D]">
                            {certificate.manufactureYear}
                          </div>
                        </div>
                        <div className="grid grid-cols-[41%_59%] bg-white/80">
                          <div className="px-3 py-1.5 pb-4 font-bold text-[#1D293D] border-r border-[#B4CBE5]">
                            Date of Handover
                          </div>
                          <div className="px-3 py-1.5 pb-4 text-[#1D293D]">
                            {formatDisplayDate(certificate.handoverDate)}
                          </div>
                        </div>
                      </div>

                      {/* Right QR Verification Panel */}
                      <div className="bg-white p-3 flex flex-col items-center justify-center text-center">
                        <div className="border border-[#CAD5E2] rounded p-1.5 bg-white">
                          {qrDataUrl ? (
                            <img
                              src={qrDataUrl}
                              alt={`QR Code for ${certificate.certificateNumber}`}
                              className="w-28 h-28 object-contain"
                            />
                          ) : (
                            <div className="w-28 h-28 bg-slate-100" />
                          )}
                        </div>
                        <div className="font-serif font-bold text-[11px] text-[#0D2847] mt-2 tracking-wide">
                          SCAN TO VERIFY
                        </div>
                        <div className="flex items-center gap-1.5 w-full max-w-[118px] my-1">
                          <div className="h-px bg-[#CAD5E2] flex-1" />
                          <svg viewBox="0 0 20 20" className="w-3 h-3 shrink-0" aria-hidden="true">
                            <path d="M16 4 C10 4, 4 9, 5 15 C11 16, 16 10, 16 4 Z" fill="#007A55" />
                          </svg>
                          <div className="h-px bg-[#CAD5E2] flex-1" />
                        </div>
                        <div className="text-[11px] font-bold text-[#0D2847]">
                          {certificate.certificateNumber}
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Section C: Terms & Certifications */}
                  <div className="mt-3">
                    <div className="bg-[#DCE8F5] border border-[#B4CBE5] px-3 py-1 font-serif font-bold text-xs text-[#143E6D]">
                      C. TERMS &amp; CERTIFICATIONS
                    </div>
                    <ol className="mt-2 space-y-1.5 text-[11px] font-serif text-[#334155]">
                      {[
                        'Parivahan Scrappers undertakes to dismantle the vehicle and process all recoverable metal, plastic, and fluid components through authorized channels compliant with environmental and recycling standards.',
                        'Once accepted for scrapping, the vehicle, its chassis, engine, or registered component parts shall not be restored, resold, re-registered, or returned to road use in any jurisdiction.',
                        'This certificate, with the scrapping video record, constitutes complete documentary proof of the vehicle disposal furnished to the customer.',
                        "This certificate is issued as proof of handover and processing intent; statutory de-registration remains the customer's responsibility with the transport authority.",
                      ].map((statement, idx) => (
                        <li key={idx} className="flex items-start gap-2">
                          <span className="inline-flex items-center justify-center w-4 h-4 rounded-full bg-[#0D2847] text-white font-sans font-bold text-[9px] shrink-0 mt-0.5">
                            {idx + 1}
                          </span>
                          <span className="leading-snug">{statement}</span>
                        </li>
                      ))}
                    </ol>
                  </div>

                  {/* Signatory, Eco Badges & Green Message Panel */}
                  <div className="mt-4 grid grid-cols-1 sm:grid-cols-[38%_36%_26%] gap-4 items-center">
                    <div>
                      <div className="font-serif font-bold text-xs text-[#0D2847]">
                        For PARIVAHAN SCRAPPERS
                      </div>
                      <div className="font-serif text-[10px] text-[#475569]">
                        ({COMPANY_SUBTITLE})
                      </div>
                      <svg viewBox="0 0 120 34" className="w-28 h-8 mt-1.5" aria-hidden="true">
                        <path
                          d="M6 26 C12 10, 20 2, 23 8 C24 14, 15 24, 17 26 C21 25, 31 11, 36 11 C40 12, 37 22, 43 24 C51 25, 62 11, 70 11 C74 12, 66 23, 70 26 C77 27, 94 18, 110 15"
                          fill="none"
                          stroke="#0D47A1"
                          strokeWidth="2.2"
                          strokeLinecap="round"
                          strokeLinejoin="round"
                        />
                      </svg>
                      <div className="border-t border-[#0D2847] w-44 pt-1 font-serif font-bold text-xs text-[#0D2847]">
                        Authorised Signatory
                      </div>
                    </div>

                    <div className="sm:border-l border-[#CAD5E2] sm:pl-4 space-y-2 text-[11px] text-[#334155]">
                      <div className="flex items-center gap-2">
                        <span className="w-5 h-5 rounded-full border border-[#006045] inline-flex items-center justify-center text-[#007A55] text-[10px] shrink-0">
                          🍃
                        </span>
                        <span>Environmentally Responsible</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="w-5 h-5 rounded-full border border-[#006045] inline-flex items-center justify-center text-[#006045] text-[10px] shrink-0">
                          ♻
                        </span>
                        <span>Resource Conservation</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="w-5 h-5 rounded-full border border-[#006045] inline-flex items-center justify-center text-[#006045] text-[10px] shrink-0">
                          🌐
                        </span>
                        <span>Sustainable Tomorrow</span>
                      </div>
                    </div>

                    <div className="bg-[#EDF7F2] border border-[#CFDFD6] px-4 py-4 text-center font-serif font-bold text-xs leading-snug text-[#143828]">
                      <div>End-of-Life</div>
                      <div>Vehicles Deserve</div>
                      <div>a Better Future.</div>
                    </div>
                  </div>

                  {/* Bottom Footer */}
                  <div className="mt-6 pt-2 border-t border-[#9EA9B5] flex flex-wrap items-center justify-between gap-2 text-[10px]">
                    <div className="text-[#475569]">
                      Computer Generated Certificate • Digitally Verified
                    </div>
                    <div className="font-bold text-[#0D2847]">Scan QR Code to Verify</div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {certificate.versionHistory && certificate.versionHistory.length > 0 && (
            <div className="mt-4 max-w-[780px] mx-auto p-3 rounded-lg bg-white border border-slate-200 text-xs text-slate-600">
              <span className="font-semibold text-[#0D2847]">Version History Preserved: </span>
              <span>
                {certificate.versionHistory.length} prior revision(s) archived with original
                canonical hashes in audit records.
              </span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
