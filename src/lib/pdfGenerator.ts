import { jsPDF } from 'jspdf';
import QRCode from 'qrcode';
import type { CertificateRecord } from '../shared/types';
import { formatChassisOrEngine } from '../shared/vehicleData';

export function buildVerificationUrl(cert: Pick<CertificateRecord, 'certificateNumber' | 'qrToken'>, customDomain?: string): string {
  const base = customDomain?.trim()
    ? customDomain.replace(/\/+$/, '')
    : typeof window !== 'undefined'
      ? window.location.origin
      : 'https://parivahan-certificate.vercel.app';

  const qs = new URLSearchParams({
    certificateNumber: cert.certificateNumber,
    token: cert.qrToken,
  });
  return `${base}/verify?${qs.toString()}`;
}

export async function generateQrDataUrl(url: string): Promise<string> {
  return QRCode.toDataURL(url, {
    errorCorrectionLevel: 'M',
    margin: 1,
    width: 240,
    color: {
      dark: '#0B1F3A',
      light: '#FFFFFF',
    },
  });
}

function formatDisplayDate(isoDate: string): string {
  if (!isoDate) return '-';
  const parts = isoDate.split('-');
  if (parts.length !== 3) return isoDate;
  return `${parts[2]}-${parts[1]}-${parts[0]}`;
}

export interface PdfBrandingOptions {
  customDomain?: string;
  authorizedSignatory?: string;
  signatoryDesignation?: string;
  unhideChassisEngine?: boolean;
}

export async function buildCertificatePdfDoc(
  cert: CertificateRecord,
  options?: PdfBrandingOptions
): Promise<{ doc: jsPDF; fileName: string; verifyUrl: string }> {
  const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();

  const navy: [number, number, number] = [11, 31, 58]; // #0B1F3A
  const emerald: [number, number, number] = [5, 150, 105]; // #059669
  const slateDark: [number, number, number] = [15, 23, 42];
  const slateMuted: [number, number, number] = [100, 116, 139];
  const borderLight: [number, number, number] = [203, 213, 225];
  const surfaceLight: [number, number, number] = [248, 250, 252];

  // Outer institutional border
  doc.setDrawColor(...navy);
  doc.setLineWidth(0.9);
  doc.rect(10, 10, pageWidth - 20, pageHeight - 20);
  doc.setDrawColor(...emerald);
  doc.setLineWidth(0.35);
  doc.rect(12, 12, pageWidth - 24, pageHeight - 24);

  // Header Banner
  doc.setFillColor(...navy);
  doc.rect(12, 12, pageWidth - 24, 34, 'F');
  doc.setFillColor(...emerald);
  doc.rect(12, 46, pageWidth - 24, 2.2, 'F');

  // Brand & Title
  doc.setTextColor(255, 255, 255);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(18);
  doc.text('PARIVAHAN SCRAPPERS', pageWidth / 2, 23, { align: 'center' });

  doc.setFontSize(10.5);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(167, 243, 208); // soft emerald tint
  doc.text('CERTIFICATE OF VEHICLE SCRAPPING (RVSF)', pageWidth / 2, 30.5, { align: 'center' });

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8.2);
  doc.setTextColor(226, 232, 240);
  doc.text(
    `${cert.facilityName}  |  RVSF Code: ${cert.facilityRvsfCode}`,
    pageWidth / 2,
    37.5,
    { align: 'center' }
  );
  doc.setFontSize(7.5);
  doc.text(cert.facilityAddress.slice(0, 110), pageWidth / 2, 42.5, { align: 'center' });

  // Key Reference Strip
  let y = 53;
  doc.setFillColor(...surfaceLight);
  doc.setDrawColor(...borderLight);
  doc.setLineWidth(0.3);
  doc.rect(16, y, pageWidth - 32, 21, 'FD');

  const colW = (pageWidth - 32) / 4;
  const keyItems = [
    { label: 'CERTIFICATE NUMBER', value: cert.certificateNumber },
    { label: 'SCRAPPING REG. NO.', value: cert.scrappingRegNumber },
    { label: 'ISSUE DATE', value: formatDisplayDate(cert.issueDate) },
    { label: 'STATUS / VERSION', value: `${cert.status} (v${cert.version})` },
  ];

  keyItems.forEach((item, idx) => {
    const x = 16 + idx * colW + 3;
    if (idx > 0) {
      doc.setDrawColor(...borderLight);
      doc.line(16 + idx * colW, y + 3, 16 + idx * colW, y + 18);
    }
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(6.8);
    doc.setTextColor(...slateMuted);
    doc.text(item.label, x, y + 7);

    doc.setFont('courier', 'bold');
    doc.setFontSize(9.2);
    if (idx === 3 && cert.status === 'CANCELLED') {
      doc.setTextColor(185, 28, 28);
    } else if (idx === 3 && cert.status === 'ACTIVE') {
      doc.setTextColor(...emerald);
    } else {
      doc.setTextColor(...navy);
    }
    doc.text(item.value, x, y + 14.5);
  });

  // Helper to render structured 2-column section
  const renderSection = (
    title: string,
    rows: Array<[string, string, string, string]>,
    startY: number
  ): number => {
    let curY = startY;
    doc.setFillColor(...navy);
    doc.rect(16, curY, pageWidth - 32, 7, 'F');
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8.5);
    doc.setTextColor(255, 255, 255);
    doc.text(title, 19, curY + 4.8);
    curY += 7;

    const halfW = (pageWidth - 32) / 2;
    const rowH = 11.5;

    rows.forEach((row, rIdx) => {
      if (rIdx % 2 === 1) {
        doc.setFillColor(248, 250, 252);
        doc.rect(16, curY, pageWidth - 32, rowH, 'F');
      }
      doc.setDrawColor(...borderLight);
      doc.setLineWidth(0.25);
      doc.rect(16, curY, halfW, rowH);
      doc.rect(16 + halfW, curY, halfW, rowH);

      // Left cell
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(6.8);
      doc.setTextColor(...slateMuted);
      doc.text(row[0], 19, curY + 4);
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(8.8);
      doc.setTextColor(...slateDark);
      doc.text(String(row[1] || '-').slice(0, 44), 19, curY + 9);

      // Right cell
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(6.8);
      doc.setTextColor(...slateMuted);
      doc.text(row[2], 19 + halfW, curY + 4);
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(8.8);
      doc.setTextColor(...slateDark);
      doc.text(String(row[3] || '-').slice(0, 44), 19 + halfW, curY + 9);

      curY += rowH;
    });

    return curY + 5;
  };

  const showFullChassisEngine = options?.unhideChassisEngine ?? cert.unhideChassisEngine === true;
  const idProofText = cert.idProofNumber
    ? `${cert.idProofType ? `${cert.idProofType}: ` : ''}${cert.idProofNumber}`
    : 'Not Provided';

  y = 79;
  y = renderSection(
    '1. REGISTERED VEHICLE OWNER PARTICULARS',
    [
      ['OWNER FULL NAME', cert.ownerName, 'HANDOVER DATE', formatDisplayDate(cert.handoverDate)],
      ['ID PROOF (OPTIONAL)', idProofText, 'RESIDENTIAL ADDRESS', (cert.ownerAddress || 'Not Provided').slice(0, 44)],
    ],
    y
  );

  y = renderSection(
    '2. SCRAPPED VEHICLE PARTICULARS',
    [
      ['RC NUMBER (VEHICLE NO.)', cert.vehicleRegNumber, 'REGISTERING AUTHORITY (RTO)', cert.rtoAuthority],
      ['MAKE / MANUFACTURER', cert.make, 'MODEL / VARIANT', cert.model],
      ['YEAR OF MANUFACTURE', String(cert.manufactureYear), 'REMARKS / CONDITION', cert.remarks || 'Verified & Scrapped'],
      [
        'CHASSIS NUMBER (VIN)',
        formatChassisOrEngine(cert.chassisNumber, showFullChassisEngine),
        'ENGINE NUMBER',
        formatChassisOrEngine(cert.engineNumber, showFullChassisEngine),
      ],
    ],
    y
  );

  // Declaration Block
  doc.setFillColor(240, 253, 244);
  doc.setDrawColor(167, 243, 208);
  doc.setLineWidth(0.35);
  doc.rect(16, y, pageWidth - 32, 16, 'FD');
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(7.5);
  doc.setTextColor(...emerald);
  doc.text('CERTIFICATION OF DESTRUCTION & DE-POLLUTION', 19, y + 5.2);
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(7.4);
  doc.setTextColor(...slateDark);
  const decl =
    'This certifies that the above motor vehicle has been physically received, verified against ownership documents, depolluted, and processed for environmentally compliant scrapping under Parivahan Scrappers RVSF procedures.';
  doc.text(doc.splitTextToSize(decl, pageWidth - 38), 19, y + 9.8);
  y += 20;

  // Cryptographic Verification & QR Section
  const verifyUrl = buildVerificationUrl(cert, options?.customDomain);
  const qrDataUrl = await generateQrDataUrl(verifyUrl);

  doc.setDrawColor(...borderLight);
  doc.setLineWidth(0.3);
  doc.rect(16, y, pageWidth - 32, 42);

  // QR Image on left
  doc.addImage(qrDataUrl, 'PNG', 19, y + 3, 35, 35);

  // Verification metadata next to QR
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(8.2);
  doc.setTextColor(...navy);
  doc.text('PUBLIC QR & CRYPTOGRAPHIC INTEGRITY VERIFICATION', 58, y + 7.5);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(7.3);
  doc.setTextColor(...slateMuted);
  doc.text('Scan the QR code or verify online without login at:', 58, y + 12.5);
  doc.setFont('courier', 'normal');
  doc.setFontSize(6.8);
  doc.setTextColor(...emerald);
  doc.text(doc.splitTextToSize(verifyUrl, 90), 58, y + 16.5);

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(6.8);
  doc.setTextColor(...slateMuted);
  doc.text('CANONICAL SHA-256 INTEGRITY DIGEST:', 58, y + 27.5);
  doc.setFont('courier', 'normal');
  doc.setFontSize(6.6);
  doc.setTextColor(...slateDark);
  doc.text(cert.canonicalHash.slice(0, 32), 58, y + 31.8);
  doc.text(cert.canonicalHash.slice(32), 58, y + 35.5);

  // Signatory Block on right
  const sigX = pageWidth - 58;
  doc.setDrawColor(...borderLight);
  doc.line(sigX - 4, y + 4, sigX - 4, y + 38);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(7.5);
  doc.setTextColor(...navy);
  doc.text('AUTHORIZED SIGNATORY', sigX + 20, y + 10, { align: 'center' });

  doc.setDrawColor(...navy);
  doc.setLineWidth(0.3);
  doc.line(sigX + 2, y + 27, sigX + 38, y + 27);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(7.6);
  doc.text(options?.authorizedSignatory || 'Authorized RVSF Officer', sigX + 20, y + 31.5, { align: 'center' });
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(6.8);
  doc.setTextColor(...slateMuted);
  doc.text(options?.signatoryDesignation || 'Parivahan Scrappers', sigX + 20, y + 35.5, { align: 'center' });

  // Cancelled overlay stamp if cancelled
  if (cert.status === 'CANCELLED') {
    doc.saveGraphicsState();
    doc.setTextColor(220, 38, 38);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(34);
    doc.text('CANCELLED', pageWidth / 2, pageHeight / 2 + 12, {
      align: 'center',
      angle: 32,
    });
    doc.restoreGraphicsState();
  }

  // Footer note
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(6.8);
  doc.setTextColor(...slateMuted);
  doc.text(
    `Issued electronically by ${cert.facilityName} on ${new Date(cert.createdAt).toLocaleString()} | Record ID: ${cert.id}`,
    pageWidth / 2,
    pageHeight - 14.5,
    { align: 'center' }
  );

  const safeFileName = `${cert.certificateNumber.replace(/\//g, '_')}_${cert.vehicleRegNumber}.pdf`;
  return { doc, fileName: safeFileName, verifyUrl };
}

export async function downloadCertificatePdf(
  cert: CertificateRecord,
  options?: PdfBrandingOptions
): Promise<void> {
  const { doc, fileName } = await buildCertificatePdfDoc(cert, options);
  doc.save(fileName);
}
