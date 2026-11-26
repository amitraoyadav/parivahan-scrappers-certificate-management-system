import React from 'react';
import { Download, ExternalLink, Eye, FileText } from 'lucide-react';
import type { CertificateRecord } from '../shared/types';
import { downloadCertificatePdf, type PdfBrandingOptions } from '../lib/pdfGenerator';

interface RecentCertificatesPanelProps {
  certificates: CertificateRecord[];
  loading: boolean;
  onPreview: (cert: CertificateRecord) => void;
  onOpenVerify: (cert: CertificateRecord) => void;
  pdfBranding?: PdfBrandingOptions;
}

export const RecentCertificatesPanel: React.FC<RecentCertificatesPanelProps> = ({
  certificates,
  loading,
  onPreview,
  onOpenVerify,
  pdfBranding,
}) => {
  return (
    <section className="bg-white border border-slate-200 rounded-xl overflow-hidden">
      <div className="px-6 py-4 border-b border-slate-200 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
        <div>
          <h2 className="font-display text-base font-bold text-[#0B1F3A]">
            Latest Five Issued Certificates
          </h2>
          <p className="text-xs text-slate-500 mt-0.5">
            Certificate Maker visibility is restricted to the 5 most recently issued records.
          </p>
        </div>
        <span className="text-xs font-mono text-slate-500 tabular-nums">
          Showing {certificates.length} / 5 max
        </span>
      </div>

      {loading ? (
        <div className="p-8 text-center text-sm text-slate-500">Loading recent certificates...</div>
      ) : certificates.length === 0 ? (
        <div className="p-10 text-center">
          <div className="w-10 h-10 rounded-lg bg-slate-100 text-slate-500 mx-auto flex items-center justify-center mb-3">
            <FileText className="w-5 h-5" />
          </div>
          <p className="font-medium text-sm text-slate-900">No Certificates Issued Yet</p>
          <p className="text-xs text-slate-500 mt-1 max-w-md mx-auto">
            This fresh registry starts at zero records. Complete the form above to issue your first
            vehicle scrapping certificate.
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
              {certificates.map((cert) => (
                <tr key={cert.id} className="hover:bg-slate-50/70 transition-colors">
                  <td className="py-3.5 px-6">
                    <div className="font-mono font-semibold text-[#0B1F3A] tabular-nums">
                      {cert.certificateNumber}
                    </div>
                    <div className="font-mono text-xs text-slate-500 tabular-nums">
                      {cert.scrappingRegNumber}
                    </div>
                  </td>
                  <td className="py-3.5 px-4">
                    <div className="font-medium text-slate-900">{cert.ownerName}</div>
                    <div className="text-xs text-slate-500">{cert.rtoAuthority}</div>
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
                    {cert.issueDate}
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
                    <div className="inline-flex items-center gap-2">
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
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
};
