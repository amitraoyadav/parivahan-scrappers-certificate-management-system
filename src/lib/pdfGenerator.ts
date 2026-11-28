import { jsPDF } from 'jspdf';
import QRCode from 'qrcode';
import type { CertificateBrand, CertificateRecord } from '../shared/types';
import { formatChassisOrEngine } from '../shared/vehicleData';

export const COMPANY_HEADER_NAME = 'PARIVAHAN SCRAPPERS';
export const COMPANY_BOTTOM_SUBTITLE = 'A UNIT OF SCRAP ROUTE';
export const SCRAP_ROUTE_HEADER_NAME = 'SCRAP ROUTE';
export const COMPANY_ADDRESS_LINE = 'B12, Dwarka, New Delhi.';
export const COMPANY_PHONE_LINE = '8506925495';
export const COMPANY_WEBSITE_LINE = 'https://parivahanscrappers.netlify.app/';

export function getCertificateBrand(
  cert: Pick<CertificateRecord, 'brand' | 'certificateNumber'>
): CertificateBrand {
  if (cert.brand === 'scrap_route' || cert.brand === 'parivahan') {
    return cert.brand;
  }
  return cert.certificateNumber?.toUpperCase().startsWith('SR/') ? 'scrap_route' : 'parivahan';
}

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

interface BrandPalette {
  primary: Rgb;
  sectionText: Rgb;
  subtitle: Rgb;
  inkDark: Rgb;
  inkBody: Rgb;
  inkMuted: Rgb;
  leafGreen: Rgb;
  smallLeafGreen: Rgb;
  bannerFill: Rgb;
  bannerText: Rgb;
  sectionFill: Rgb;
  tableBorder: Rgb;
  subtleBorder: Rgb;
  footerRule: Rgb;
  signatureBlue: Rgb;
  greenBoxFill: Rgb;
  greenBoxBorder: Rgb;
  greenBoxText: Rgb;
  watermarkStroke: Rgb;
  watermarkText: Rgb;
}

const PARIVAHAN_COLORS: BrandPalette = {
  primary: [13, 40, 71], // #0D2847
  sectionText: [20, 62, 109], // #143E6D
  subtitle: [30, 58, 95], // #1E3A5F
  inkDark: [29, 41, 61], // #1D293D
  inkBody: [51, 65, 85], // #334155
  inkMuted: [71, 85, 105], // #475569
  leafGreen: [0, 96, 69], // #006045
  smallLeafGreen: [0, 122, 85], // #007A55
  bannerFill: [225, 238, 230], // #E1EEE6
  bannerText: [34, 77, 54], // #224D36
  sectionFill: [220, 232, 245], // #DCE8F5
  tableBorder: [180, 203, 229], // #B4CBE5
  subtleBorder: [202, 213, 226], // #CAD5E2
  footerRule: [158, 169, 181], // #9EA9B5
  signatureBlue: [13, 71, 161], // #0D47A1
  greenBoxFill: [237, 247, 242], // #EDF7F2
  greenBoxBorder: [207, 223, 214], // #CFDFD6
  greenBoxText: [20, 56, 40], // #143828
  watermarkStroke: [222, 227, 224], // #DEE3E0
  watermarkText: [224, 228, 226], // #E0E4E2
};

const SCRAP_ROUTE_COLORS: BrandPalette = {
  primary: [20, 34, 48], // #142230 refined charcoal-slate
  sectionText: [6, 95, 70], // #065F46 deep recycling emerald
  subtitle: [30, 58, 52], // #1E3A34
  inkDark: [26, 36, 48], // #1A2430
  inkBody: [51, 65, 85], // #334155
  inkMuted: [71, 85, 105], // #475569
  leafGreen: [5, 110, 78], // #056E4E
  smallLeafGreen: [4, 120, 87], // #047857
  bannerFill: [224, 242, 233], // #E0F2E9
  bannerText: [6, 78, 59], // #064E3B
  sectionFill: [227, 241, 234], // #E3F1EA
  tableBorder: [179, 212, 198], // #B3D4C6
  subtleBorder: [198, 214, 206], // #C6D6CE
  footerRule: [156, 174, 166], // #9CAEA6
  signatureBlue: [15, 76, 129], // #0F4C81
  greenBoxFill: [236, 248, 242], // #ECF8F2
  greenBoxBorder: [189, 220, 206], // #BDDCCE
  greenBoxText: [15, 61, 46], // #0F3D2E
  watermarkStroke: [220, 229, 224], // #DCE5E0
  watermarkText: [222, 230, 226], // #DEE6E2
};

function getBrandPalette(brand: CertificateBrand): BrandPalette {
  return brand === 'scrap_route' ? SCRAP_ROUTE_COLORS : PARIVAHAN_COLORS;
}

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
  const safeText = String(text ?? '').replace(/\s+/g, ' ').trim();
  if (!safeText) return;
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
function drawHeaderLeafIcon(
  doc: jsPDF,
  cx: number,
  topY: number,
  width: number,
  height: number,
  palette: BrandPalette
): void {
  const halfW = width / 2;
  const bottomY = topY + height;

  doc.setFillColor(...palette.leafGreen);
  doc.setDrawColor(...palette.leafGreen);
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
  doc.setDrawColor(...palette.leafGreen);
  doc.setLineWidth(0.42);
  doc.line(cx, bottomY - 0.2, cx, bottomY + 0.75);
}

/**
 * Draws the solid small tilted green leaf accent (above green banner, QR divider, and eco badge 1).
 */
function drawSmallTiltedLeaf(
  doc: jsPDF,
  cx: number,
  cy: number,
  size: number,
  palette: BrandPalette
): void {
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

  doc.setFillColor(...palette.smallLeafGreen);
  doc.lines(segs, pts[0][0], pts[0][1], [1, 1], 'F', true);

  // Subtle tiny stem at base
  const [s1x, s1y] = rot(-halfL * 1.18, 0.12);
  const [s2x, s2y] = rot(-halfL * 0.72, 0);
  doc.setDrawColor(...palette.smallLeafGreen);
  doc.setLineWidth(0.28);
  doc.line(s1x, s1y, s2x, s2y);
}

/**
 * Draws the crisp monochrome contact icons in the top-left header.
 */
function drawPinIcon(doc: jsPDF, cx: number, cy: number, color: Rgb): void {
  doc.setDrawColor(...color);
  doc.setLineWidth(0.28);
  const r = 1.05;
  doc.circle(cx, cy - 0.45, r, 'S');
  doc.line(cx - r * 0.82, cy + 0.15, cx, cy + 1.45);
  doc.line(cx + r * 0.82, cy + 0.15, cx, cy + 1.45);
  doc.setFillColor(...color);
  doc.circle(cx, cy - 0.45, 0.35, 'F');
}

function drawPhoneIcon(doc: jsPDF, cx: number, cy: number, color: Rgb): void {
  doc.setDrawColor(...color);
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
function drawCircularWatermark(
  doc: jsPDF,
  cx: number,
  cy: number,
  brandHeaderName: string,
  palette: BrandPalette
): void {
  const outerR = 66.0;
  const dashR = 63.4;
  const innerRingR = 61.1;
  const centerRingR = 45.0;

  doc.saveGraphicsState();

  // Outer thick solid ring
  doc.setDrawColor(...palette.watermarkStroke);
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

  // Curved text along top arc: brand name (PARIVAHAN SCRAPPERS or SCRAP ROUTE)
  doc.setTextColor(...palette.watermarkText);
  doc.setFont('times', 'bold');
  doc.setFontSize(14.0);
  const topText = brandHeaderName;
  const topRadius = 52.6;
  const topSpanDeg = topText.length <= 12 ? 84 : 122;
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
function drawBlueSignatureStroke(
  doc: jsPDF,
  startX: number,
  baseY: number,
  palette: BrandPalette
): void {
  doc.saveGraphicsState();
  doc.setDrawColor(...palette.signatureBlue);
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
function drawEcoBadges(
  doc: jsPDF,
  iconCx: number,
  textX: number,
  startY: number,
  palette: BrandPalette
): void {
  const rowGap = 5.8;
  const r = 2.05;

  // Row 1: Solid green leaf inside circular border
  const y1 = startY;
  doc.setDrawColor(...palette.leafGreen);
  doc.setLineWidth(0.28);
  doc.circle(iconCx, y1, r, 'S');
  drawSmallTiltedLeaf(doc, iconCx, y1, 2.0, palette);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(7.6);
  doc.setTextColor(...palette.inkBody);
  doc.text('Environmentally Responsible', textX, y1 + 0.9);

  // Row 2: Circular recycle arrows inside circular border
  const y2 = startY + rowGap;
  doc.setDrawColor(...palette.leafGreen);
  doc.setLineWidth(0.28);
  doc.circle(iconCx, y2, r, 'S');
  const ir = 1.05;
  doc.setLineWidth(0.24);
  doc.setFillColor(...palette.leafGreen);
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
  doc.setTextColor(...palette.inkBody);
  doc.text('Resource Conservation', textX, y2 + 0.9);

  // Row 3: Globe inside circular border
  const y3 = startY + rowGap * 2;
  doc.setDrawColor(...palette.leafGreen);
  doc.setLineWidth(0.28);
  doc.circle(iconCx, y3, r, 'S');
  drawGlobeIcon(doc, iconCx, y3, 1.3, palette.leafGreen);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(7.6);
  doc.setTextColor(...palette.inkBody);
  doc.text('Sustainable Tomorrow', textX, y3 + 0.9);
}

/**
 * Draws the introductory paragraph with crisp word spacing and inline bold brand name.
 */
function drawIntroParagraph(
  doc: jsPDF,
  x: number,
  y: number,
  maxWidth: number,
  brandHeaderName: string,
  palette: BrandPalette
): void {
  const words: Array<{ text: string; bold: boolean }> = [
    ...'This is to certify that the motor vehicle mentioned below has been received by'
      .split(' ')
      .map((text) => ({ text, bold: false })),
    { text: brandHeaderName, bold: true },
    ...'for dismantling and environmentally sound recycling, in accordance with the provisions of the Vehicle Scrappage Policy and all applicable environmental regulations.'
      .split(' ')
      .map((text) => ({ text, bold: false })),
  ];

  const fontSize = 9.35;
  const lineHeight = 4.65;
  doc.setFont('times', 'normal');
  doc.setFontSize(fontSize);
  doc.setTextColor(...palette.inkDark);

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
  const brand = getCertificateBrand(cert);
  const isScrapRoute = brand === 'scrap_route';
  const palette = getBrandPalette(brand);
  const brandHeaderName = isScrapRoute ? SCRAP_ROUTE_HEADER_NAME : COMPANY_HEADER_NAME;

  const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
  const pageWidth = doc.internal.pageSize.getWidth(); // 210
  const pageHeight = doc.internal.pageSize.getHeight(); // 297

  const contentX = 8.9;
  const contentRight = 201.0;
  const contentW = contentRight - contentX; // 192.1mm
  const centerX = pageWidth / 2; // 105mm

  // =========================================================================
  // 1. DOUBLE-LINE OUTER BORDER
  // =========================================================================
  doc.setDrawColor(...palette.primary);
  doc.setLineWidth(0.6);
  doc.rect(4.6, 4.6, pageWidth - 9.2, pageHeight - 9.2);
  doc.setLineWidth(0.25);
  doc.rect(6.1, 6.1, pageWidth - 12.2, pageHeight - 12.2);

  // =========================================================================
  // 2. SUBTLE CIRCULAR WATERMARK BEHIND CENTRAL CONTENT
  // =========================================================================
  drawCircularWatermark(doc, centerX, 148.8, brandHeaderName, palette);

  // =========================================================================
  // 3. TOP HEADER — BRANDING & RESPONSIBLE RECYCLING PANEL
  // =========================================================================
  doc.setFont('times', 'bold');
  doc.setFontSize(isScrapRoute ? 24.5 : 23.2);
  doc.setTextColor(...palette.primary);
  doc.text(brandHeaderName, contentX, 17.6);

  // Contact Rows with crisp vector icons (NO top subtitle; website shown ONLY on Parivahan)
  const iconX = 10.4;
  const contactTextX = 14.2;
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8.3);
  doc.setTextColor(...palette.inkDark);

  drawPinIcon(doc, iconX, isScrapRoute ? 26.8 : 25.4, palette.primary);
  doc.text(COMPANY_ADDRESS_LINE, contactTextX, isScrapRoute ? 27.6 : 26.2);

  drawPhoneIcon(doc, iconX, isScrapRoute ? 32.8 : 31.0, palette.primary);
  doc.text(COMPANY_PHONE_LINE, contactTextX, isScrapRoute ? 33.7 : 31.9);

  if (!isScrapRoute) {
    drawGlobeIcon(doc, iconX, 36.8, 1.35, palette.primary);
    doc.setTextColor(...palette.primary);
    doc.text(COMPANY_WEBSITE_LINE, contactTextX, 37.6);
  }

  // Vertical Header Divider
  doc.setDrawColor(...palette.primary);
  doc.setLineWidth(0.28);
  doc.line(150.7, 9.5, 150.7, 40.6);

  // Top-Right Responsible Recycling Logo & Text
  drawHeaderLeafIcon(doc, 164.0, 19.6, 6.4, 10.2, palette);

  doc.setFont('times', 'bold');
  doc.setFontSize(10.6);
  doc.setTextColor(...palette.primary);
  doc.text('Responsible', 174.3, 21.3);
  doc.text('Recycling', 174.3, 25.9);
  doc.setTextColor(...palette.leafGreen);
  doc.text('Greener India', 174.3, 30.5);

  // Header Horizontal Divider
  doc.setDrawColor(...palette.primary);
  doc.setLineWidth(0.42);
  doc.line(contentX, 44.5, contentRight, 44.5);

  // =========================================================================
  // 4. CERTIFICATE METADATA ROW (Certificate No. & Date of Issue)
  // =========================================================================
  doc.setFont('times', 'bold');
  doc.setFontSize(10.5);
  doc.setTextColor(...palette.primary);
  doc.text(`Certificate No. : ${cert.certificateNumber}`, contentX, 50.8);
  doc.text(`Date of Issue : ${formatDisplayDate(cert.issueDate)}`, contentRight, 50.8, {
    align: 'right',
  });

  // =========================================================================
  // 5. MAIN TITLE, REGULATORY SUBTITLE, LEAF & SUSTAINABILITY BANNER
  // =========================================================================
  doc.setFont('times', 'bold');
  doc.setFontSize(20.0);
  doc.setTextColor(...palette.primary);
  doc.text('VEHICLE SCRAPPING CERTIFICATE', centerX, 62.2, { align: 'center' });

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(7.1);
  doc.setTextColor(...palette.subtitle);
  drawCenteredSpacedText(
    doc,
    'ISSUED IN ACCORDANCE WITH APPLICABLE VEHICLE SCRAPPAGE REGULATIONS',
    centerX,
    68.4,
    0.42
  );

  // Small centered solid green leaf above banner
  drawSmallTiltedLeaf(doc, centerX, 72.7, 3.0, palette);

  // Pale-green Sustainability Banner
  doc.setFillColor(...palette.bannerFill);
  doc.rect(51.65, 76.2, 106.7, 6.4, 'F');
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(7.6);
  doc.setTextColor(...palette.bannerText);
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
  drawIntroParagraph(doc, contentX, 87.9, contentW, brandHeaderName, palette);

  // =========================================================================
  // 7. SECTION A — OWNER DETAILS (Address & ID Proof are optional)
  // =========================================================================
  const secAY = 101.8;
  const secAHdrH = 6.0;
  const ownerSplitX = 73.3;

  const trimmedAddress = (cert.ownerAddress ?? '').trim();
  const trimmedIdNumber = (cert.idProofNumber ?? '').trim();
  const formattedIdProof = trimmedIdNumber
    ? `${cert.idProofType ? `${cert.idProofType}: ` : ''}${trimmedIdNumber}`
    : '';

  interface OwnerRowSpec {
    label: string;
    value: string;
    kind: 'name' | 'address' | 'id';
  }

  const ownerRows: OwnerRowSpec[] = [
    { label: 'Owner Name', value: cert.ownerName.toUpperCase(), kind: 'name' },
  ];
  if (trimmedAddress) {
    ownerRows.push({ label: 'Address', value: trimmedAddress, kind: 'address' });
  }
  if (formattedIdProof) {
    ownerRows.push({ label: 'ID Proof Number', value: formattedIdProof, kind: 'id' });
  }

  const ownerLabelX = contentX + 2.6;
  const ownerValX = ownerSplitX + 2.6;
  const ownerValMaxW = contentRight - ownerValX - 2.6;

  // Measure whether address wraps to 2 lines when only 2 rows are rendered
  let addressWrapsTwoLines = false;
  if (trimmedAddress) {
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8.4);
    const addrLines = doc.splitTextToSize(trimmedAddress.replace(/\s+/g, ' '), ownerValMaxW) as string[];
    addressWrapsTwoLines = addrLines.length > 1;
  }

  const secABodyH =
    ownerRows.length === 3
      ? 21.8
      : ownerRows.length === 2
        ? addressWrapsTwoLines
          ? 17.6
          : 14.8
        : 8.0;

  // Section A Header Bar
  doc.setFillColor(...palette.sectionFill);
  doc.setDrawColor(...palette.tableBorder);
  doc.setLineWidth(0.3);
  doc.rect(contentX, secAY, contentW, secAHdrH, 'FD');

  doc.setFont('times', 'bold');
  doc.setFontSize(9.5);
  doc.setTextColor(...palette.sectionText);
  doc.text('A. OWNER DETAILS', contentX + 2.6, secAY + 4.15);

  // Section A White Table Body (opaque white masks watermark cleanly inside owner fields)
  const ownerBodyY = secAY + secAHdrH;
  doc.setFillColor(255, 255, 255);
  doc.setDrawColor(...palette.tableBorder);
  doc.setLineWidth(0.3);
  doc.rect(contentX, ownerBodyY, contentW, secABodyH, 'FD');
  doc.line(ownerSplitX, ownerBodyY, ownerSplitX, ownerBodyY + secABodyH);

  ownerRows.forEach((row, idx) => {
    const rowBaselineY =
      ownerRows.length === 1 ? ownerBodyY + 5.2 : ownerBodyY + 5.1 + idx * 7.1;

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8.7);
    doc.setTextColor(...palette.inkDark);
    doc.text(row.label, ownerLabelX, rowBaselineY);

    if (row.kind === 'name') {
      doc.setTextColor(...palette.primary);
      drawFittedSingleLine(
        doc,
        row.value,
        ownerValX,
        rowBaselineY,
        ownerValMaxW,
        'helvetica',
        'bold',
        8.7,
        6.8
      );
    } else if (row.kind === 'address') {
      doc.setTextColor(...palette.inkBody);
      drawFittedMultiLine(
        doc,
        row.value,
        ownerValX,
        rowBaselineY,
        ownerValMaxW,
        2,
        'helvetica',
        'normal',
        8.4,
        3.6,
        6.5
      );
    } else {
      doc.setTextColor(...palette.inkBody);
      drawFittedSingleLine(
        doc,
        row.value,
        ownerValX,
        rowBaselineY,
        ownerValMaxW,
        'helvetica',
        'normal',
        8.4,
        6.8
      );
    }
  });

  // Automatically redistribute space saved when optional Address/ID rows are omitted
  // (savedSpace === 0 when all 3 rows are present, preserving exact reference coordinates)
  const savedSpace = Math.max(0, 21.8 - secABodyH);
  const secABottom = ownerBodyY + secABodyH;

  // =========================================================================
  // 8. SECTION B — VEHICLE DETAILS + QR VERIFICATION PANEL
  // =========================================================================
  const secBY = Number((secABottom + 2.3 + savedSpace * 0.15).toFixed(2));
  const secBHdrH = 6.2;

  // Section B Header Bar
  doc.setFillColor(...palette.sectionFill);
  doc.setDrawColor(...palette.tableBorder);
  doc.setLineWidth(0.3);
  doc.rect(contentX, secBY, contentW, secBHdrH, 'FD');

  doc.setFont('times', 'bold');
  doc.setFontSize(9.5);
  doc.setTextColor(...palette.sectionText);
  doc.text('B. VEHICLE DETAILS', contentX + 2.6, secBY + 4.25);

  // Main Vehicle Table + QR Panel Box (1.4mm gap below header matches reference)
  const vehTableY = Number((secBY + secBHdrH + 1.4).toFixed(2));
  const vehTableH = 58.3;
  const vehSplitX = 68.9;
  const qrPanelX = 154.8;
  const qrPanelW = contentRight - qrPanelX; // 46.2mm
  const qrCenterX = qrPanelX + qrPanelW / 2; // 177.9mm

  // Solid white fill behind vehicle rows text and QR panel, leaving the bottom strip open
  // so the curved watermark bottom arc peeks through cleanly.
  doc.setFillColor(255, 255, 255);
  doc.rect(contentX, vehTableY, qrPanelX - contentX, 52.0, 'F');
  doc.rect(qrPanelX, vehTableY, qrPanelW, vehTableH, 'F');

  doc.setDrawColor(...palette.tableBorder);
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
      rowHeight: 6.75,
    },
    {
      label: 'Chassis No.',
      value: displayChassis,
      boldValue: false,
      drawBottomBorder: true,
      rowHeight: 6.75,
    },
    {
      label: 'Engine No.',
      value: displayEngine,
      boldValue: false,
      drawBottomBorder: false,
      rowHeight: 6.75,
    },
    {
      label: 'Maker (Bike Brand)',
      value: cert.make,
      boldValue: false,
      drawBottomBorder: false,
      rowHeight: 6.75,
    },
    {
      label: 'Model',
      value: cert.model,
      boldValue: false,
      drawBottomBorder: true,
      rowHeight: 6.75,
    },
    {
      label: 'Year of Manufacture',
      value: String(cert.manufactureYear),
      boldValue: false,
      drawBottomBorder: true,
      rowHeight: 6.75,
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
    const baselineY = curRowY + (idx === vehicleRows.length - 1 ? 4.6 : 4.55);

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8.5);
    doc.setTextColor(...palette.inkDark);
    doc.text(row.label, vehLabelX, baselineY);

    doc.setTextColor(...(row.boldValue ? palette.primary : palette.inkDark));
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
      doc.setDrawColor(...palette.tableBorder);
      doc.setLineWidth(0.28);
      doc.line(contentX, curRowY, qrPanelX, curRowY);
    }
  });

  // Right QR Verification Panel (positioned relative to vehTableY)
  const verifyUrl = buildVerificationUrl(cert, options?.customDomain);
  const qrDataUrl = await generateQrDataUrl(verifyUrl);

  const qrBoxSize = 33.4;
  const qrBoxX = qrCenterX - qrBoxSize / 2; // 161.2mm
  const qrBoxY = vehTableY + 5.3;
  doc.setDrawColor(...palette.subtleBorder);
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
  doc.setTextColor(...palette.primary);
  doc.text('SCAN TO VERIFY', qrCenterX, vehTableY + 42.3, { align: 'center' });

  // Subtle horizontal rule split by solid small green leaf
  const qrDividerY = vehTableY + 46.2;
  doc.setDrawColor(...palette.subtleBorder);
  doc.setLineWidth(0.24);
  doc.line(qrBoxX, qrDividerY, qrCenterX - 3.6, qrDividerY);
  doc.line(qrCenterX + 3.6, qrDividerY, qrBoxX + qrBoxSize, qrDividerY);
  drawSmallTiltedLeaf(doc, qrCenterX, qrDividerY, 2.4, palette);

  // Dynamic Certificate Number below QR
  doc.setTextColor(...palette.primary);
  drawFittedSingleLine(
    doc,
    cert.certificateNumber,
    qrCenterX,
    vehTableY + 52.3,
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
  const secCY = Number((vehTableY + vehTableH + 2.7 + savedSpace * 0.2).toFixed(2));
  const secCHdrH = 5.6;

  doc.setFillColor(...palette.sectionFill);
  doc.setDrawColor(...palette.tableBorder);
  doc.setLineWidth(0.3);
  doc.rect(contentX, secCY, contentW, secCHdrH, 'FD');

  doc.setFont('times', 'bold');
  doc.setFontSize(9.5);
  doc.setTextColor(...palette.sectionText);
  doc.text('C. TERMS & CERTIFICATIONS', contentX + 2.6, secCY + 3.9);

  const extraTermStep = Number((savedSpace * 0.06).toFixed(2));
  const brandProseName = isScrapRoute ? 'Scrap Route' : 'Parivahan Scrappers';
  const terms: Array<{ num: string; text: string; y: number }> = [
    {
      num: '1',
      text: `${brandProseName} undertakes to dismantle the vehicle and process all recoverable metal, plastic, and fluid components through authorized channels compliant with environmental and recycling standards.`,
      y: secCY + 9.9,
    },
    {
      num: '2',
      text: 'Once accepted for scrapping, the vehicle, its chassis, engine, or registered component parts shall not be restored, resold, re-registered, or returned to road use in any jurisdiction.',
      y: secCY + 17.9 + extraTermStep,
    },
    {
      num: '3',
      text: 'This certificate, with the scrapping video record, constitutes complete documentary proof of the vehicle disposal furnished to the customer.',
      y: secCY + 25.9 + extraTermStep * 2,
    },
    {
      num: '4',
      text: "This certificate is issued as proof of handover and processing intent; statutory de-registration remains the customer's responsibility with the transport authority.",
      y: secCY + 31.5 + extraTermStep * 3,
    },
  ];

  const badgeCx = 10.7;
  const termTextX = 14.8;
  const termMaxW = contentRight - termTextX - 0.5;

  for (const term of terms) {
    doc.setFillColor(...palette.primary);
    doc.circle(badgeCx, term.y - 0.7, 1.85, 'F');
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(6.6);
    doc.setTextColor(255, 255, 255);
    doc.text(term.num, badgeCx, term.y + 0.1, { align: 'center' });

    doc.setFont('times', 'normal');
    doc.setFontSize(8.2);
    doc.setTextColor(...palette.inkBody);
    const wrapped = doc.splitTextToSize(term.text, termMaxW) as string[];
    wrapped.forEach((line, idx) => {
      doc.text(line, termTextX, term.y + idx * 3.45);
    });
  }

  // =========================================================================
  // 10. AUTHORISATION, ENVIRONMENTAL RESPONSIBILITY & GREEN MESSAGE PANEL
  // =========================================================================
  const authBaseY = Number((secCY + 36.9 + extraTermStep * 3 + savedSpace * 0.25).toFixed(2));

  // Left: Brand Authorisation & Signature
  // Parivahan: Line 1 "PARIVAHAN SCRAPPERS", Line 2 "A UNIT OF SCRAP ROUTE"
  // Scrap Route: Line 1 "SCRAP ROUTE" ONLY (no Parivahan wording, no second subtitle)
  doc.setFont('times', 'bold');
  doc.setFontSize(9.2);
  doc.setTextColor(...palette.primary);
  doc.text(brandHeaderName, contentX, authBaseY + 2.6);

  if (!isScrapRoute) {
    doc.setFont('times', 'bold');
    doc.setFontSize(7.5);
    doc.setTextColor(...palette.inkMuted);
    doc.text(COMPANY_BOTTOM_SUBTITLE, contentX, authBaseY + 6.0);
  }

  // Handwritten Blue Signature
  drawBlueSignatureStroke(doc, 11.6, authBaseY + 9.9, palette);

  // Signature Rule & Label
  doc.setDrawColor(...palette.primary);
  doc.setLineWidth(0.32);
  doc.line(contentX, authBaseY + 17.9, 54.7, authBaseY + 17.9);

  doc.setFont('times', 'bold');
  doc.setFontSize(8.8);
  doc.setTextColor(...palette.primary);
  doc.text('Authorised Signatory', contentX, authBaseY + 21.7);

  // Middle: Vertical Divider + 3 Environmental Responsibility Badges
  doc.setDrawColor(...palette.subtleBorder);
  doc.setLineWidth(0.25);
  doc.line(89.8, authBaseY + 3.6, 89.8, authBaseY + 20.0);
  drawEcoBadges(doc, 95.0, 99.0, authBaseY + 6.1, palette);

  // Right: Green Message Panel
  const greenBoxX = 154.8;
  const greenBoxY = authBaseY;
  const greenBoxW = 46.2;
  const greenBoxH = 23.0;
  const greenBoxCx = greenBoxX + greenBoxW / 2;

  doc.setFillColor(...palette.greenBoxFill);
  doc.setDrawColor(...palette.greenBoxBorder);
  doc.setLineWidth(0.35);
  doc.rect(greenBoxX, greenBoxY, greenBoxW, greenBoxH, 'FD');

  doc.setFont('times', 'bold');
  doc.setFontSize(9.4);
  doc.setTextColor(...palette.greenBoxText);
  doc.text('End-of-Life', greenBoxCx, greenBoxY + 8.8, { align: 'center' });
  doc.text('Vehicles Deserve', greenBoxCx, greenBoxY + 12.8, { align: 'center' });
  doc.text('a Better Future.', greenBoxCx, greenBoxY + 16.8, { align: 'center' });

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
  doc.setDrawColor(...palette.footerRule);
  doc.setLineWidth(0.28);
  doc.line(contentX, 283.5, contentRight, 283.5);

  // Small minimal laptop/document icon on bottom-left
  doc.setDrawColor(...palette.inkMuted);
  doc.setLineWidth(0.28);
  doc.rect(9.3, 285.4, 2.3, 1.55, 'S');
  doc.line(8.9, 287.2, 12.0, 287.2);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(7.1);
  doc.setTextColor(...palette.inkMuted);
  doc.text('Computer Generated Certificate • Digitally Verified', 15.1, 287.2);

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(7.1);
  doc.setTextColor(...palette.primary);
  doc.text('Scan QR Code to Verify', contentRight, 287.2, { align: 'right' });

  const safeFileName = getCertificatePdfFilename(cert.certificateNumber);
  return { doc, fileName: safeFileName, verifyUrl };
}

export function getCertificatePdfFilename(certificateNumber: string): string {
  const sanitized = certificateNumber
    .trim()
    .replace(/[\\/]+/g, '-')
    .replace(/[^A-Za-z0-9._-]/g, '-');
  return `${sanitized}.pdf`;
}

export async function downloadCertificatePdf(
  cert: CertificateRecord,
  options?: PdfBrandingOptions
): Promise<string> {
  const { doc, fileName } = await buildCertificatePdfDoc(cert, options);
  doc.save(fileName);
  return fileName;
}

export async function openAndDownloadCertificatePdf(
  cert: CertificateRecord,
  options?: PdfBrandingOptions
): Promise<{ fileName: string; blobUrl: string; openedInNewTab: boolean }> {
  const { doc, fileName } = await buildCertificatePdfDoc(cert, options);
  const blob = doc.output('blob');
  const blobUrl = URL.createObjectURL(blob);

  // Attempt to open in a new browser tab; gracefully report if blocked by popup blocker
  let openedInNewTab = false;
  try {
    const openedWin = window.open(blobUrl, '_blank', 'noopener,noreferrer');
    if (openedWin && !openedWin.closed) {
      openedInNewTab = true;
    }
  } catch {
    openedInNewTab = false;
  }

  // Automatically trigger file download with exact certificate number filename
  const link = document.createElement('a');
  link.href = blobUrl;
  link.download = fileName;
  link.rel = 'noopener noreferrer';
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);

  return { fileName, blobUrl, openedInNewTab };
}
