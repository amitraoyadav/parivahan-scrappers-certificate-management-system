import { jsPDF } from 'jspdf';
import QRCode from 'qrcode';
import type { CertificateRecord } from '../shared/types';
import { formatChassisOrEngine } from '../shared/vehicleData';

export const COMPANY_HEADER_NAME = 'PARIVAHAN SCRAPPERS';
export const COMPANY_SUBTITLE = 'A Unit OF Scrapping Yard Ltd.';
export const COMPANY_ADDRESS_LINE = 'B12, Dwarka, New Delhi.';
export const COMPANY_PHONE_LINE = '8506925495';
export const COMPANY_WEBSITE_LINE = 'https://parivahan-scrappers.netlify.app/';

export function buildVerificationUrl(
  cert: Pick<CertificateRecord, 'certificateNumber' | 'qrToken'>,
  customDomain?: string
): string {
  const base = customDomain?.trim()
    ? customDomain.replace(/\/+$/, '')
    : typeof window !== 'undefined'
      ? window.location.origin
      : '';

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
    width: 360,
    color: {
      dark: '#000000',
      light: '#FFFFFF',
    },
  });
}

export function formatDisplayDate(isoDate: string): string {
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

type Rgb = [number, number, number];

const COLORS = {
  navy: [13, 40, 71] as Rgb, // #0D2847
  navySection: [20, 62, 109] as Rgb, // #143E6D
  navySubtitle: [30, 58, 95] as Rgb, // #1E3A5F
  inkDark: [29, 41, 61] as Rgb, // #1D293D
  inkBody: [51, 65, 85] as Rgb, // #334155
  inkMuted: [71, 85, 105] as Rgb, // #475569
  leafGreen: [0, 96, 69] as Rgb, // #006045
  smallLeafGreen: [0, 122, 85] as Rgb, // #007A55
  bannerFill: [225, 238, 230] as Rgb, // #E1EEE6
  bannerText: [34, 77, 54] as Rgb, // #224D36
  sectionFill: [220, 232, 245] as Rgb, // #DCE8F5
  tableBorder: [180, 203, 229] as Rgb, // #B4CBE5
  subtleBorder: [202, 213, 226] as Rgb, // #CAD5E2
  footerRule: [158, 169, 181] as Rgb, // #9EA9B5
  signatureBlue: [13, 71, 161] as Rgb, // #0D47A1
  greenBoxFill: [237, 247, 242] as Rgb, // #EDF7F2
  greenBoxBorder: [207, 223, 214] as Rgb, // #CFDFD6
  greenBoxText: [20, 56, 40] as Rgb, // #143828
  watermarkStroke: [222, 227, 224] as Rgb, // #DEE3E0
  watermarkText: [224, 228, 226] as Rgb, // #E0E4E2
};

/**
 * Draws centered text with exact letter-spacing compensation (fixes jsPDF charSpace center drift).
 */
function drawCenteredSpacedText(
  doc: jsPDF,
  text: string,
  centerX: number,
  y: number,
  charSpaceMm: number
): void {
  const baseWidth = doc.getTextWidth(text);
  const spacedWidth = baseWidth + charSpaceMm * Math.max(0, text.length - 1);
  doc.text(text, centerX - spacedWidth / 2, y, { charSpace: charSpaceMm });
}

/**
 * Draws a single-line string fitted neatly within maxWidth by reducing font size smoothly if needed.
 */
function drawFittedSingleLine(
  doc: jsPDF,
  text: string,
  x: number,
  y: number,
  maxWidth: number,
  font: 'helvetica' | 'times' | 'courier',
  style: 'normal' | 'bold',
  baseSize: number,
  minSize = 6.5,
  align: 'left' | 'center' | 'right' = 'left'
): void {
  const safeText = String(text || '-').replace(/\s+/g, ' ').trim() || '-';
  let size = baseSize;
  doc.setFont(font, style);
  doc.setFontSize(size);

  while (size > minSize && doc.getTextWidth(safeText) > maxWidth) {
    size = Math.max(minSize, Number((size - 0.35).toFixed(2)));
    doc.setFontSize(size);
  }

  let output = safeText;
  if (doc.getTextWidth(output) > maxWidth) {
    while (output.length > 3 && doc.getTextWidth(`${output}...`) > maxWidth) {
      output = output.slice(0, -1);
    }
    output = `${output}...`;
  }

  doc.text(output, x, y, { align });
}

/**
 * Draws a multi-line value constrained strictly inside maxWidth and maxLines.
 */
function drawFittedMultiLine(
  doc: jsPDF,
  text: string,
  x: number,
  y: number,
  maxWidth: number,
  maxLines: number,
  font: 'helvetica' | 'times',
  style: 'normal' | 'bold',
  baseSize: number,
  lineHeight: number,
  minSize = 6.5
): void {
  const safeText = String(text || 'Not Provided').replace(/\s+/g, ' ').trim() || 'Not Provided';
  let size = baseSize;
  doc.setFont(font, style);
  doc.setFontSize(size);

  let lines = doc.splitTextToSize(safeText, maxWidth) as string[];
  while (lines.length > maxLines && size > minSize) {
    size = Math.max(minSize, Number((size - 0.4).toFixed(2)));
    doc.setFontSize(size);
    lines = doc.splitTextToSize(safeText, maxWidth) as string[];
  }

  if (lines.length > maxLines) {
    lines = lines.slice(0, maxLines);
    let last = lines[maxLines - 1];
    while (last.length > 3 && doc.getTextWidth(`${last}...`) > maxWidth) {
      last = last.slice(0, -1);
    }
    lines[maxLines - 1] = `${last}...`;
  }

  const effectiveLH = lines.length > 1 ? Math.min(lineHeight, size * 0.42) : lineHeight;
  const startY = lines.length > 1 ? y - effectiveLH * 0.35 : y;
  lines.forEach((line, idx) => {
    doc.text(line, x, startY + idx * effectiveLH);
  });
}

/**
 * Draws the sleek upright Responsible Recycling green leaf emblem at top-right,
 * matching the almond leaf silhouette with single crisp vertical white midrib.
 */
function drawHeaderLeafIcon(doc: jsPDF, cx: number, topY: number, width: number, height: number): void {
  const halfW = width / 2;
  const bottomY = topY + height;

  doc.setFillColor(...COLORS.leafGreen);
  doc.setDrawColor(...COLORS.leafGreen);
  doc.setLineWidth(0.08);

  const pts: Array<[number, number]> = [];
  const steps = 28;
  for (let i = 0; i <= steps; i++) {
    const t = i / steps;
    const x = cx + halfW * Math.sin(Math.PI * Math.pow(t, 0.92));
    const y = topY + height * t;
    pts.push([x, y]);
  }
  for (let i = steps; i >= 0; i--) {
    const t = i / steps;
    const x = cx - halfW * Math.sin(Math.PI * Math.pow(t, 0.92));
    const y = topY + height * t;
    pts.push([x, y]);
  }

  const segs: Array<[number, number]> = [];
  for (let i = 1; i < pts.length; i++) {
    segs.push([pts[i][0] - pts[i - 1][0], pts[i][1] - pts[i - 1][1]]);
  }
  doc.lines(segs, pts[0][0], pts[0][1], [1, 1], 'F', true);

  // Clean vertical white center vein + subtle lower stem
  doc.setDrawColor(255, 255, 255);
  doc.setLineWidth(0.32);
  doc.line(cx, topY + height * 0.16, cx, bottomY - height * 0.06);
  doc.setDrawColor(...COLORS.leafGreen);
  doc.setLineWidth(0.42);
  doc.line(cx, bottomY - 0.2, cx, bottomY + 0.75);
}

/**
 * Draws the solid small tilted green leaf accent (above green banner, QR divider, and eco badge 1).
 */
function drawSmallTiltedLeaf(doc: jsPDF, cx: number, cy: number, size: number): void {
  const angle = -Math.PI / 4;
  const cos = Math.cos(angle);
  const sin = Math.sin(angle);
  const rot = (lx: number, ly: number): [number, number] => [
    cx + lx * cos - ly * sin,
    cy + lx * sin + ly * cos,
  ];

  const halfL = size * 0.58;
  const halfW = size * 0.36;
  const pts: Array<[number, number]> = [];
  const steps = 18;
  for (let i = 0; i <= steps; i++) {
    const t = i / steps;
    const lx = -halfL + 2 * halfL * t;
    const ly = -halfW * Math.sin(Math.PI * Math.pow(t, 0.85));
    pts.push(rot(lx, ly));
  }
  for (let i = steps; i >= 0; i--) {
    const t = i / steps;
    const lx = -halfL + 2 * halfL * t;
    const ly = halfW * Math.sin(Math.PI * Math.pow(t, 0.85));
    pts.push(rot(lx, ly));
  }

  const segs: Array<[number, number]> = [];
  for (let i = 1; i < pts.length; i++) {
    segs.push([pts[i][0] - pts[i - 1][0], pts[i][1] - pts[i - 1][1]]);
  }

  doc.setFillColor(...COLORS.smallLeafGreen);
  doc.lines(segs, pts[0][0], pts[0][1], [1, 1], 'F', true);

  // Subtle tiny stem at base
  const [s1x, s1y] = rot(-halfL * 1.18, 0.12);
  const [s2x, s2y] = rot(-halfL * 0.72, 0);
  doc.setDrawColor(...COLORS.smallLeafGreen);
  doc.setLineWidth(0.28);
  doc.line(s1x, s1y, s2x, s2y);
}

/**
 * Draws the 3 crisp monochrome contact icons in the top-left header.
 */
function drawPinIcon(doc: jsPDF, cx: number, cy: number): void {
  doc.setDrawColor(...COLORS.navy);
  doc.setLineWidth(0.28);
  const r = 1.05;
  doc.circle(cx, cy - 0.45, r, 'S');
  doc.line(cx - r * 0.82, cy + 0.15, cx, cy + 1.45);
  doc.line(cx + r * 0.82, cy + 0.15, cx, cy + 1.45);
  doc.setFillColor(...COLORS.navy);
  doc.circle(cx, cy - 0.45, 0.35, 'F');
}

function drawPhoneIcon(doc: jsPDF, cx: number, cy: number): void {
  doc.setDrawColor(...COLORS.navy);
  doc.setLineWidth(0.32);
  const pts: Array<[number, number]> = [
    [cx - 1.05, cy - 1.1],
    [cx - 0.45, cy - 1.1],
    [cx - 0.2, cy - 0.55],
    [cx - 0.55, cy - 0.2],
    [cx + 0.2, cy + 0.55],
    [cx + 0.55, cy + 0.2],
    [cx + 1.1, cy + 0.45],
    [cx + 1.1, cy + 1.05],
    [cx + 0.55, cy + 1.15],
    [cx - 0.35, cy + 0.65],
    [cx - 0.85, cy + 0.15],
    [cx - 1.15, cy - 0.55],
  ];
  const segs: Array<[number, number]> = [];
  for (let i = 1; i < pts.length; i++) {
    segs.push([pts[i][0] - pts[i - 1][0], pts[i][1] - pts[i - 1][1]]);
  }
  doc.lines(segs, pts[0][0], pts[0][1], [1, 1], 'S', true);
}

function drawGlobeIcon(doc: jsPDF, cx: number, cy: number, r: number, color: Rgb): void {
  doc.setDrawColor(...color);
  doc.setLineWidth(0.24);
  doc.circle(cx, cy, r, 'S');
  doc.ellipse(cx, cy, r * 0.48, r, 'S');
  doc.line(cx - r, cy, cx + r, cy);
  doc.line(cx - r * 0.84, cy - r * 0.48, cx + r * 0.84, cy - r * 0.48);
  doc.line(cx - r * 0.84, cy + r * 0.48, cx + r * 0.84, cy + r * 0.48);
}

/**
 * Draws the subtle circular watermark behind the central certificate content.
 * Matches the exact circular rings, top/bottom curved text arcs, and faint inner emblem
 * visible behind the intro paragraph, Owner/Vehicle tables, and Section C in PS-26-R1001042.pdf.
 */
function drawCircularWatermark(doc: jsPDF, cx: number, cy: number): void {
  const outerR = 66.0;
  const dashR = 63.4;
  const innerRingR = 61.1;
  const centerRingR = 45.0;

  doc.saveGraphicsState();

  // Outer thick solid ring
  doc.setDrawColor(...COLORS.watermarkStroke);
  doc.setLineWidth(1.0);
  doc.circle(cx, cy, outerR, 'S');

  // Middle dashed ring (deterministic manual arc segments)
  doc.setLineWidth(0.55);
  const dashCount = 72;
  const step = (Math.PI * 2) / dashCount;
  for (let i = 0; i < dashCount; i++) {
    const a1 = i * step;
    const a2 = a1 + step * 0.52;
    doc.line(
      cx + dashR * Math.cos(a1),
      cy + dashR * Math.sin(a1),
      cx + dashR * Math.cos(a2),
      cy + dashR * Math.sin(a2)
    );
  }

  // Inner solid ring
  doc.setLineWidth(0.45);
  doc.circle(cx, cy, innerRingR, 'S');

  // Inner emblem circle
  doc.setLineWidth(0.35);
  doc.circle(cx, cy, centerRingR, 'S');

  // Curved text along top arc: PARIVAHAN SCRAPPERS
  doc.setTextColor(...COLORS.watermarkText);
  doc.setFont('times', 'bold');
  doc.setFontSize(14.0);
  const topText = 'PARIVAHAN SCRAPPERS';
  const topRadius = 52.6;
  const topSpanDeg = 122;
  const topStartDeg = -90 - topSpanDeg / 2;
  const topStepDeg = topSpanDeg / Math.max(1, topText.length - 1);

  for (let i = 0; i < topText.length; i++) {
    const ch = topText[i];
    if (ch === ' ') continue;
    const deg = topStartDeg + i * topStepDeg;
    const rad = (deg * Math.PI) / 180;
    const tx = cx + topRadius * Math.cos(rad);
    const ty = cy + topRadius * Math.sin(rad);
    const rotDeg = -(deg + 90);
    doc.text(ch, tx, ty, { align: 'center', angle: rotDeg });
  }

  // Curved text along bottom arc: RESPONSIBLE RECYCLING • GREENER INDIA
  // Positioned at radius 47.4 (center 148.8 -> bottom 196.2mm) so it curves cleanly
  // across the open lower area of Section B right above Section C just like the reference.
  doc.setFont('times', 'bold');
  doc.setFontSize(9.8);
  const bottomText = 'RESPONSIBLE RECYCLING  •  GREENER INDIA';
  const bottomRadius = 47.6;
  const bottomSpanDeg = 136;
  const bottomStartDeg = 90 + bottomSpanDeg / 2;
  const bottomStepDeg = bottomSpanDeg / Math.max(1, bottomText.length - 1);

  for (let i = 0; i < bottomText.length; i++) {
    const ch = bottomText[i];
    if (ch === ' ') continue;
    const deg = bottomStartDeg - i * bottomStepDeg;
    const rad = (deg * Math.PI) / 180;
    const tx = cx + bottomRadius * Math.cos(rad);
    const ty = cy + bottomRadius * Math.sin(rad);
    const rotDeg = 90 - deg;
    doc.text(ch, tx, ty, { align: 'center', angle: rotDeg });
  }

  doc.restoreGraphicsState();
}

/**
 * Draws the handwritten blue-ink authorised signatory flourish matching the reference PDF.
 */
function drawBlueSignatureStroke(doc: jsPDF, startX: number, baseY: number): void {
  doc.saveGraphicsState();
  doc.setDrawColor(...COLORS.signatureBlue);
  doc.setLineWidth(0.44);
  doc.setLineCap('round');
  doc.setLineJoin('round');

  const pts: Array<[number, number]> = [
    [0.0, 5.1],
    [0.8, 2.7],
    [1.9, 0.7],
    [3.1, 0.0],
    [3.8, 0.6],
    [3.5, 2.3],
    [2.7, 4.3],
    [2.3, 5.4],
    [3.1, 5.1],
    [4.8, 3.1],
    [6.4, 1.7],
    [7.5, 1.6],
    [7.7, 2.7],
    [7.9, 4.3],
    [9.1, 5.0],
    [11.0, 4.5],
    [13.0, 3.0],
    [14.8, 1.7],
    [16.3, 1.5],
    [16.8, 2.5],
    [15.8, 4.1],
    [14.8, 5.2],
    [15.6, 5.5],
    [17.9, 4.8],
    [21.2, 3.8],
    [24.3, 3.0],
    [25.8, 2.7],
  ];

  for (let i = 1; i < pts.length; i++) {
    doc.line(
      startX + pts[i - 1][0],
      baseY + pts[i - 1][1],
      startX + pts[i][0],
      baseY + pts[i][1]
    );
  }
  doc.restoreGraphicsState();
}

/**
 * Draws the 3 Environmental Responsibility circular icons in the bottom middle section.
 */
function drawEcoBadges(doc: jsPDF, iconCx: number, textX: number, startY: number): void {
  const rowGap = 5.8;
  const r = 2.05;

  // Row 1: Solid green leaf inside circular border
  const y1 = startY;
  doc.setDrawColor(...COLORS.leafGreen);
  doc.setLineWidth(0.28);
  doc.circle(iconCx, y1, r, 'S');
  drawSmallTiltedLeaf(doc, iconCx, y1, 2.0);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(7.6);
  doc.setTextColor(...COLORS.inkBody);
  doc.text('Environmentally Responsible', textX, y1 + 0.9);

  // Row 2: Circular recycle arrows inside circular border
  const y2 = startY + rowGap;
  doc.setDrawColor(...COLORS.leafGreen);
  doc.setLineWidth(0.28);
  doc.circle(iconCx, y2, r, 'S');
  const ir = 1.05;
  doc.setLineWidth(0.24);
  doc.setFillColor(...COLORS.leafGreen);
  for (let arc = 0; arc < 2; arc++) {
    const startDeg = arc === 0 ? -155 : 25;
    const endDeg = arc === 0 ? -25 : 155;
    let prevX = iconCx + ir * Math.cos((startDeg * Math.PI) / 180);
    let prevY = y2 + ir * Math.sin((startDeg * Math.PI) / 180);
    for (let d = startDeg + 15; d <= endDeg; d += 15) {
      const nx = iconCx + ir * Math.cos((d * Math.PI) / 180);
      const ny = y2 + ir * Math.sin((d * Math.PI) / 180);
      doc.line(prevX, prevY, nx, ny);
      prevX = nx;
      prevY = ny;
    }
    const tipX = iconCx + ir * Math.cos((endDeg * Math.PI) / 180);
    const tipY = y2 + ir * Math.sin((endDeg * Math.PI) / 180);
    doc.circle(tipX, tipY, 0.24, 'F');
  }

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(7.6);
  doc.setTextColor(...COLORS.inkBody);
  doc.text('Resource Conservation', textX, y2 + 0.9);

  // Row 3: Globe inside circular border
  const y3 = startY + rowGap * 2;
  doc.setDrawColor(...COLORS.leafGreen);
  doc.setLineWidth(0.28);
  doc.circle(iconCx, y3, r, 'S');
  drawGlobeIcon(doc, iconCx, y3, 1.3, COLORS.leafGreen);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(7.6);
  doc.setTextColor(...COLORS.inkBody);
  doc.text('Sustainable Tomorrow', textX, y3 + 0.9);
}

/**
 * Draws the introductory paragraph with crisp word spacing and inline bold "PARIVAHAN SCRAPPERS".
 */
function drawIntroParagraph(doc: jsPDF, x: number, y: number, maxWidth: number): void {
  const words: Array<{ text: string; bold: boolean }> = [
    ...'This is to certify that the motor vehicle mentioned below has been received by'
      .split(' ')
      .map((text) => ({ text, bold: false })),
    { text: 'PARIVAHAN SCRAPPERS', bold: true },
    ...'(A Unit OF Scrapping Yard Ltd.) for dismantling and environmentally sound recycling, in accordance with the provisions of the Vehicle Scrappage Policy and all applicable environmental regulations.'
      .split(' ')
      .map((text) => ({ text, bold: false })),
  ];

  const fontSize = 9.35;
  const lineHeight = 4.65;
  doc.setFont('times', 'normal');
  doc.setFontSize(fontSize);
  doc.setTextColor(...COLORS.inkDark);

  const naturalSpaceW = Math.max(doc.getTextWidth(' '), 0.95);

  // Measure each word accurately in its own style (with slight safety cushion on bold phrase)
  const measured = words.map((w) => {
    doc.setFont('times', w.bold ? 'bold' : 'normal');
    const rawW = doc.getTextWidth(w.text);
    return { ...w, width: w.bold ? rawW + 0.6 : rawW };
  });

  // Greedy word-wrap
  const lines: Array<typeof measured> = [];
  let currentLine: typeof measured = [];
  let currentW = 0;

  for (const w of measured) {
    const needed = currentLine.length === 0 ? w.width : naturalSpaceW + w.width;
    if (currentLine.length > 0 && currentW + needed > maxWidth) {
      lines.push(currentLine);
      currentLine = [w];
      currentW = w.width;
    } else {
      currentLine.push(w);
      currentW += needed;
    }
  }
  if (currentLine.length > 0) {
    lines.push(currentLine);
  }

  // Render lines with crisp full-line justification (never compressing below naturalSpaceW)
  lines.forEach((line, lineIdx) => {
    const isLastLine = lineIdx === lines.length - 1;
    const wordsTotalW = line.reduce((acc, w) => acc + w.width, 0);
    const gaps = Math.max(0, line.length - 1);
    const gapW =
      !isLastLine && gaps > 0 && maxWidth - wordsTotalW > gaps * naturalSpaceW
        ? Math.min((maxWidth - wordsTotalW) / gaps, naturalSpaceW * 2.1)
        : naturalSpaceW;

    let cursorX = x;
    const baselineY = y + lineIdx * lineHeight;
    line.forEach((w, idx) => {
      doc.setFont('times', w.bold ? 'bold' : 'normal');
      doc.text(w.text, cursorX, baselineY);
      cursorX += w.width + (idx < line.length - 1 ? gapW : 0);
    });
  });
}

export async function buildCertificatePdfDoc(
  cert: CertificateRecord,
  options?: PdfBrandingOptions
): Promise<{ doc: jsPDF; fileName: string; verifyUrl: string }> {
  const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
  const pageWidth = doc.internal.pageSize.getWidth(); // 210
  const pageHeight = doc.internal.pageSize.getHeight(); // 297

  const contentX = 8.9;
  const contentRight = 201.0;
  const contentW = contentRight - contentX; // 192.1mm
  const centerX = pageWidth / 2; // 105mm

  // =========================================================================
  // 1. DOUBLE-LINE NAVY OUTER BORDER (exact match to PS-26-R1001042.pdf)
  // =========================================================================
  doc.setDrawColor(...COLORS.navy);
  doc.setLineWidth(0.6);
  doc.rect(4.6, 4.6, pageWidth - 9.2, pageHeight - 9.2);
  doc.setLineWidth(0.25);
  doc.rect(6.1, 6.1, pageWidth - 12.2, pageHeight - 12.2);

  // =========================================================================
  // 2. SUBTLE CIRCULAR WATERMARK BEHIND CENTRAL CONTENT
  // =========================================================================
  drawCircularWatermark(doc, centerX, 148.8);

  // =========================================================================
  // 3. TOP HEADER — COMPANY BRANDING & RESPONSIBLE RECYCLING PANEL
  // =========================================================================
  doc.setFont('times', 'bold');
  doc.setFontSize(23.2);
  doc.setTextColor(...COLORS.navy);
  doc.text(COMPANY_HEADER_NAME, contentX, 15.2);

  doc.setFont('times', 'bold');
  doc.setFontSize(11.0);
  doc.setTextColor(...COLORS.inkDark);
  doc.text(COMPANY_SUBTITLE, contentX, 21.6);

  // Contact Rows with crisp vector icons
  const iconX = 10.4;
  const contactTextX = 14.2;
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8.3);
  doc.setTextColor(...COLORS.inkDark);

  drawPinIcon(doc, iconX, 28.0);
  doc.text(COMPANY_ADDRESS_LINE, contactTextX, 28.8);

  drawPhoneIcon(doc, iconX, 33.2);
  doc.text(COMPANY_PHONE_LINE, contactTextX, 34.1);

  drawGlobeIcon(doc, iconX, 38.6, 1.35, COLORS.navy);
  doc.setTextColor(...COLORS.navy);
  doc.text(COMPANY_WEBSITE_LINE, contactTextX, 39.4);

  // Vertical Header Divider
  doc.setDrawColor(...COLORS.navy);
  doc.setLineWidth(0.28);
  doc.line(150.7, 9.5, 150.7, 40.6);

  // Top-Right Responsible Recycling Logo & Text
  drawHeaderLeafIcon(doc, 164.0, 19.6, 6.4, 10.2);

  doc.setFont('times', 'bold');
  doc.setFontSize(10.6);
  doc.setTextColor(...COLORS.navy);
  doc.text('Responsible', 174.3, 21.3);
  doc.text('Recycling', 174.3, 25.9);
  doc.setTextColor(...COLORS.leafGreen);
  doc.text('Greener India', 174.3, 30.5);

  // Header Horizontal Divider
  doc.setDrawColor(...COLORS.navy);
  doc.setLineWidth(0.42);
  doc.line(contentX, 44.5, contentRight, 44.5);

  // =========================================================================
  // 4. CERTIFICATE METADATA ROW (Certificate No. & Date of Issue)
  // =========================================================================
  doc.setFont('times', 'bold');
  doc.setFontSize(10.5);
  doc.setTextColor(...COLORS.navy);
  doc.text(`Certificate No. : ${cert.certificateNumber}`, contentX, 50.8);
  doc.text(`Date of Issue : ${formatDisplayDate(cert.issueDate)}`, contentRight, 50.8, {
    align: 'right',
  });

  // =========================================================================
  // 5. MAIN TITLE, REGULATORY SUBTITLE, LEAF & SUSTAINABILITY BANNER
  // =========================================================================
  doc.setFont('times', 'bold');
  doc.setFontSize(20.0);
  doc.setTextColor(...COLORS.navy);
  doc.text('VEHICLE SCRAPPING CERTIFICATE', centerX, 62.2, { align: 'center' });

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(7.1);
  doc.setTextColor(...COLORS.navySubtitle);
  drawCenteredSpacedText(
    doc,
    'ISSUED IN ACCORDANCE WITH APPLICABLE VEHICLE SCRAPPAGE REGULATIONS',
    centerX,
    68.4,
    0.42
  );

  // Small centered solid green leaf above banner
  drawSmallTiltedLeaf(doc, centerX, 72.7, 3.0);

  // Pale-green Sustainability Banner
  doc.setFillColor(...COLORS.bannerFill);
  doc.rect(51.65, 76.2, 106.7, 6.4, 'F');
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(7.6);
  doc.setTextColor(...COLORS.bannerText);
  drawCenteredSpacedText(
    doc,
    'RESPONSIBLE SCRAPPING FOR A GREENER TOMORROW',
    centerX,
    80.35,
    0.34
  );

  // =========================================================================
  // 6. INTRODUCTORY PARAGRAPH
  // =========================================================================
  drawIntroParagraph(doc, contentX, 87.9, contentW);

  // =========================================================================
  // 7. SECTION A — OWNER DETAILS
  // =========================================================================
  const secAY = 101.8;
  const secAHdrH = 6.0;
  const secABodyH = 21.8;
  const ownerSplitX = 73.3;

  // Section A Header Bar
  doc.setFillColor(...COLORS.sectionFill);
  doc.setDrawColor(...COLORS.tableBorder);
  doc.setLineWidth(0.3);
  doc.rect(contentX, secAY, contentW, secAHdrH, 'FD');

  doc.setFont('times', 'bold');
  doc.setFontSize(9.5);
  doc.setTextColor(...COLORS.navySection);
  doc.text('A. OWNER DETAILS', contentX + 2.6, secAY + 4.15);

  // Section A White Table Body (opaque white masks watermark cleanly inside owner fields)
  const ownerBodyY = secAY + secAHdrH;
  doc.setFillColor(255, 255, 255);
  doc.setDrawColor(...COLORS.tableBorder);
  doc.setLineWidth(0.3);
  doc.rect(contentX, ownerBodyY, contentW, secABodyH, 'FD');
  doc.line(ownerSplitX, ownerBodyY, ownerSplitX, ownerBodyY + secABodyH);

  const ownerLabelX = contentX + 2.6;
  const ownerValX = ownerSplitX + 2.6;
  const ownerValMaxW = contentRight - ownerValX - 2.6;

  const idProofText = cert.idProofNumber
    ? `${cert.idProofType ? `${cert.idProofType}: ` : ''}${cert.idProofNumber}`
    : 'Not Provided';

  // Row 1: Owner Name
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(8.7);
  doc.setTextColor(...COLORS.inkDark);
  doc.text('Owner Name', ownerLabelX, ownerBodyY + 5.1);
  doc.setTextColor(...COLORS.navy);
  drawFittedSingleLine(
    doc,
    cert.ownerName.toUpperCase(),
    ownerValX,
    ownerBodyY + 5.1,
    ownerValMaxW,
    'helvetica',
    'bold',
    8.7,
    6.8
  );

  // Row 2: Address
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(8.7);
  doc.setTextColor(...COLORS.inkDark);
  doc.text('Address', ownerLabelX, ownerBodyY + 12.2);
  doc.setTextColor(...COLORS.inkBody);
  drawFittedMultiLine(
    doc,
    cert.ownerAddress || 'Not Provided',
    ownerValX,
    ownerBodyY + 12.2,
    ownerValMaxW,
    2,
    'helvetica',
    'normal',
    8.4,
    3.6,
    6.5
  );

  // Row 3: ID Proof Number
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(8.7);
  doc.setTextColor(...COLORS.inkDark);
  doc.text('ID Proof Number', ownerLabelX, ownerBodyY + 19.3);
  doc.setTextColor(...COLORS.inkBody);
  drawFittedSingleLine(
    doc,
    idProofText,
    ownerValX,
    ownerBodyY + 19.3,
    ownerValMaxW,
    'helvetica',
    'normal',
    8.4,
    6.8
  );

  // =========================================================================
  // 8. SECTION B — VEHICLE DETAILS + QR VERIFICATION PANEL
  // =========================================================================
  const secBY = 131.9;
  const secBHdrH = 6.2;

  // Section B Header Bar
  doc.setFillColor(...COLORS.sectionFill);
  doc.setDrawColor(...COLORS.tableBorder);
  doc.setLineWidth(0.3);
  doc.rect(contentX, secBY, contentW, secBHdrH, 'FD');

  doc.setFont('times', 'bold');
  doc.setFontSize(9.5);
  doc.setTextColor(...COLORS.navySection);
  doc.text('B. VEHICLE DETAILS', contentX + 2.6, secBY + 4.25);

  // Main Vehicle Table + QR Panel Box (1.4mm gap below header matches reference)
  const vehTableY = 139.5;
  const vehTableH = 58.3; // ends at 197.8mm
  const vehSplitX = 68.9;
  const qrPanelX = 154.8;
  const qrPanelW = contentRight - qrPanelX; // 46.2mm
  const qrCenterX = qrPanelX + qrPanelW / 2; // 177.9mm

  // Solid white fill behind vehicle rows 1-9 text (up to y=191.5mm) and QR panel,
  // leaving the bottom strip (191.5..197.8mm) open so the curved watermark bottom arc
  // ("RESPONSIBLE RECYCLING • GREENER INDIA") peeks through identically to PS-26-R1001042.pdf.
  doc.setFillColor(255, 255, 255);
  doc.rect(contentX, vehTableY, qrPanelX - contentX, 52.0, 'F');
  doc.rect(qrPanelX, vehTableY, qrPanelW, vehTableH, 'F');

  doc.setDrawColor(...COLORS.tableBorder);
  doc.setLineWidth(0.3);
  doc.rect(contentX, vehTableY, contentW, vehTableH, 'S');
  doc.line(vehSplitX, vehTableY, vehSplitX, vehTableY + vehTableH);
  doc.line(qrPanelX, vehTableY, qrPanelX, vehTableY + vehTableH);

  const showFullChassisEngine = options?.unhideChassisEngine ?? cert.unhideChassisEngine === true;
  const displayChassis = formatChassisOrEngine(cert.chassisNumber, showFullChassisEngine);
  const displayEngine = formatChassisOrEngine(cert.engineNumber, showFullChassisEngine);

  interface VehicleRowSpec {
    label: string;
    value: string;
    boldValue?: boolean;
    drawBottomBorder: boolean;
    rowHeight: number;
  }

  const vehicleRows: VehicleRowSpec[] = [
    {
      label: 'Registration No. for Scrapping',
      value: cert.scrappingRegNumber,
      boldValue: true,
      drawBottomBorder: true,
      rowHeight: 5.85,
    },
    {
      label: 'Vehicle Reg. (RC) No.',
      value: cert.vehicleRegNumber,
      boldValue: true,
      drawBottomBorder: true,
      rowHeight: 5.85,
    },
    {
      label: 'Chassis No.',
      value: displayChassis,
      boldValue: false,
      drawBottomBorder: true,
      rowHeight: 5.85,
    },
    {
      label: 'Engine No.',
      value: displayEngine,
      boldValue: false,
      drawBottomBorder: false,
      rowHeight: 5.85,
    },
    {
      label: 'Maker (Bike Brand)',
      value: cert.make,
      boldValue: false,
      drawBottomBorder: false,
      rowHeight: 5.85,
    },
    {
      label: 'Model',
      value: cert.model,
      boldValue: false,
      drawBottomBorder: false,
      rowHeight: 5.85,
    },
    {
      label: 'Location',
      value: cert.rtoAuthority,
      boldValue: false,
      drawBottomBorder: true,
      rowHeight: 5.85,
    },
    {
      label: 'Year of Manufacture',
      value: String(cert.manufactureYear),
      boldValue: false,
      drawBottomBorder: true,
      rowHeight: 5.85,
    },
    {
      label: 'Date of Handover',
      value: formatDisplayDate(cert.handoverDate),
      boldValue: false,
      drawBottomBorder: false,
      rowHeight: 11.5,
    },
  ];

  const vehLabelX = contentX + 2.6;
  const vehValX = vehSplitX + 2.6;
  const vehValMaxW = qrPanelX - vehValX - 2.4;

  let curRowY = vehTableY;
  vehicleRows.forEach((row, idx) => {
    const baselineY = curRowY + (idx === vehicleRows.length - 1 ? 4.3 : 4.1);

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8.5);
    doc.setTextColor(...COLORS.inkDark);
    doc.text(row.label, vehLabelX, baselineY);

    doc.setTextColor(...(row.boldValue ? COLORS.navy : COLORS.inkDark));
    drawFittedSingleLine(
      doc,
      row.value,
      vehValX,
      baselineY,
      vehValMaxW,
      'helvetica',
      row.boldValue ? 'bold' : 'normal',
      8.5,
      6.6
    );

    curRowY += row.rowHeight;
    if (row.drawBottomBorder) {
      doc.setDrawColor(...COLORS.tableBorder);
      doc.setLineWidth(0.28);
      doc.line(contentX, curRowY, qrPanelX, curRowY);
    }
  });

  // Right QR Verification Panel
  const verifyUrl = buildVerificationUrl(cert, options?.customDomain);
  const qrDataUrl = await generateQrDataUrl(verifyUrl);

  const qrBoxSize = 33.4;
  const qrBoxX = qrCenterX - qrBoxSize / 2; // 161.2mm
  const qrBoxY = 144.8;
  doc.setDrawColor(...COLORS.subtleBorder);
  doc.setLineWidth(0.28);
  doc.roundedRect(qrBoxX, qrBoxY, qrBoxSize, qrBoxSize, 1.0, 1.0, 'S');

  // Crisp pure-black QR image centered inside box
  const qrImgSize = 30.2;
  doc.addImage(
    qrDataUrl,
    'PNG',
    qrCenterX - qrImgSize / 2,
    qrBoxY + (qrBoxSize - qrImgSize) / 2,
    qrImgSize,
    qrImgSize
  );

  // "SCAN TO VERIFY"
  doc.setFont('times', 'bold');
  doc.setFontSize(8.2);
  doc.setTextColor(...COLORS.navy);
  doc.text('SCAN TO VERIFY', qrCenterX, 181.8, { align: 'center' });

  // Subtle horizontal rule split by solid small green leaf
  const qrDividerY = 185.7;
  doc.setDrawColor(...COLORS.subtleBorder);
  doc.setLineWidth(0.24);
  doc.line(qrBoxX, qrDividerY, qrCenterX - 3.6, qrDividerY);
  doc.line(qrCenterX + 3.6, qrDividerY, qrBoxX + qrBoxSize, qrDividerY);
  drawSmallTiltedLeaf(doc, qrCenterX, qrDividerY, 2.4);

  // Dynamic Certificate Number below QR
  doc.setTextColor(...COLORS.navy);
  drawFittedSingleLine(
    doc,
    cert.certificateNumber,
    qrCenterX,
    191.8,
    qrPanelW - 4,
    'helvetica',
    'bold',
    8.2,
    6.8,
    'center'
  );

  // =========================================================================
  // 9. SECTION C — TERMS & CERTIFICATIONS
  // =========================================================================
  const secCY = 200.5;
  const secCHdrH = 5.6;

  doc.setFillColor(...COLORS.sectionFill);
  doc.setDrawColor(...COLORS.tableBorder);
  doc.setLineWidth(0.3);
  doc.rect(contentX, secCY, contentW, secCHdrH, 'FD');

  doc.setFont('times', 'bold');
  doc.setFontSize(9.5);
  doc.setTextColor(...COLORS.navySection);
  doc.text('C. TERMS & CERTIFICATIONS', contentX + 2.6, secCY + 3.9);

  const terms: Array<{ num: string; text: string; y: number }> = [
    {
      num: '1',
      text: 'Parivahan Scrappers undertakes to dismantle the vehicle and process all recoverable metal, plastic, and fluid components through authorized channels compliant with environmental and recycling standards.',
      y: 210.4,
    },
    {
      num: '2',
      text: 'Once accepted for scrapping, the vehicle, its chassis, engine, or registered component parts shall not be restored, resold, re-registered, or returned to road use in any jurisdiction.',
      y: 218.4,
    },
    {
      num: '3',
      text: 'This certificate, with the scrapping video record, constitutes complete documentary proof of the vehicle disposal furnished to the customer.',
      y: 226.4,
    },
    {
      num: '4',
      text: "This certificate is issued as proof of handover and processing intent; statutory de-registration remains the customer's responsibility with the transport authority.",
      y: 232.0,
    },
  ];

  const badgeCx = 10.7;
  const termTextX = 14.8;
  const termMaxW = contentRight - termTextX - 0.5;

  for (const term of terms) {
    doc.setFillColor(...COLORS.navy);
    doc.circle(badgeCx, term.y - 0.7, 1.85, 'F');
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(6.6);
    doc.setTextColor(255, 255, 255);
    doc.text(term.num, badgeCx, term.y + 0.1, { align: 'center' });

    doc.setFont('times', 'normal');
    doc.setFontSize(8.2);
    doc.setTextColor(...COLORS.inkBody);
    const wrapped = doc.splitTextToSize(term.text, termMaxW) as string[];
    wrapped.forEach((line, idx) => {
      doc.text(line, termTextX, term.y + idx * 3.45);
    });
  }

  // =========================================================================
  // 10. AUTHORISATION, ENVIRONMENTAL RESPONSIBILITY & GREEN MESSAGE PANEL
  // =========================================================================
  // Left: Company Authorisation & Signature
  doc.setFont('times', 'bold');
  doc.setFontSize(9.0);
  doc.setTextColor(...COLORS.navy);
  doc.text('For PARIVAHAN SCRAPPERS', contentX, 240.0);

  doc.setFont('times', 'normal');
  doc.setFontSize(7.6);
  doc.setTextColor(...COLORS.inkMuted);
  doc.text(`(${COMPANY_SUBTITLE})`, contentX, 243.2);

  // Handwritten Blue Signature
  drawBlueSignatureStroke(doc, 11.6, 247.3);

  // Signature Rule & Label
  doc.setDrawColor(...COLORS.navy);
  doc.setLineWidth(0.32);
  doc.line(contentX, 255.3, 54.7, 255.3);

  doc.setFont('times', 'bold');
  doc.setFontSize(8.8);
  doc.setTextColor(...COLORS.navy);
  doc.text('Authorised Signatory', contentX, 259.1);

  // Middle: Vertical Divider + 3 Environmental Responsibility Badges
  doc.setDrawColor(...COLORS.subtleBorder);
  doc.setLineWidth(0.25);
  doc.line(89.8, 241.0, 89.8, 257.4);
  drawEcoBadges(doc, 95.0, 99.0, 243.5);

  // Right: Green Message Panel
  const greenBoxX = 154.8;
  const greenBoxY = 237.4;
  const greenBoxW = 46.2;
  const greenBoxH = 23.0;
  const greenBoxCx = greenBoxX + greenBoxW / 2;

  doc.setFillColor(...COLORS.greenBoxFill);
  doc.setDrawColor(...COLORS.greenBoxBorder);
  doc.setLineWidth(0.35);
  doc.rect(greenBoxX, greenBoxY, greenBoxW, greenBoxH, 'FD');

  doc.setFont('times', 'bold');
  doc.setFontSize(9.4);
  doc.setTextColor(...COLORS.greenBoxText);
  doc.text('End-of-Life', greenBoxCx, 246.2, { align: 'center' });
  doc.text('Vehicles Deserve', greenBoxCx, 250.2, { align: 'center' });
  doc.text('a Better Future.', greenBoxCx, 254.2, { align: 'center' });

  // =========================================================================
  // 11. CANCELLED STAMP OVERLAY (ONLY IF STATUS IS CANCELLED)
  // =========================================================================
  if (cert.status === 'CANCELLED') {
    doc.saveGraphicsState();
    doc.setTextColor(220, 38, 38);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(34);
    doc.text('CANCELLED', centerX, pageHeight / 2 + 10, {
      align: 'center',
      angle: 32,
    });
    doc.restoreGraphicsState();
  }

  // =========================================================================
  // 12. BOTTOM FOOTER
  // =========================================================================
  doc.setDrawColor(...COLORS.footerRule);
  doc.setLineWidth(0.28);
  doc.line(contentX, 283.5, contentRight, 283.5);

  // Small minimal laptop/document icon on bottom-left
  doc.setDrawColor(...COLORS.inkMuted);
  doc.setLineWidth(0.28);
  doc.rect(9.3, 285.4, 2.3, 1.55, 'S');
  doc.line(8.9, 287.2, 12.0, 287.2);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(7.1);
  doc.setTextColor(...COLORS.inkMuted);
  doc.text('Computer Generated Certificate • Digitally Verified', 15.1, 287.2);

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(7.1);
  doc.setTextColor(...COLORS.navy);
  doc.text('Scan QR Code to Verify', contentRight, 287.2, { align: 'right' });

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
