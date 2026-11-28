export const COMMON_MANUFACTURERS: readonly string[] = [
  'Hero MotoCorp',
  'Yamaha',
  'Bajaj',
  'HERO',
  'HERO HONDA',
  'TVS',
  'Royal Enfield',
  'Suzuki',
] as const;

export const ALL_PRESET_MANUFACTURERS: string[] = [...COMMON_MANUFACTURERS];

export const OTHER_MANUFACTURER_VALUE = '__OTHER__';

/**
 * Masks Chassis or Engine numbers with XXXX at the start and XX at the end.
 * Example: "MA3EJKD1S00123451" -> "XXXXJKD1S001234XX"
 * Example: "K12MN4567891"      -> "XXXXN45678XX"
 * Short values (<= 6 chars)    -> "XXXXXX"
 */
export function maskVehicleIdNumber(value: string): string {
  const cleaned = value.trim().toUpperCase();
  if (!cleaned) return 'XXXXXX';
  if (cleaned.length <= 6) {
    return 'XXXXXX';
  }
  const middle = cleaned.slice(4, -2);
  return `XXXX${middle}XX`;
}

/**
 * Formats Chassis or Engine number for certificate preview / PDF output.
 * Hidden as XXXX...XX by default unless unhide is checked.
 */
export function formatChassisOrEngine(value: string, unhide = false): string {
  const cleaned = value.trim().toUpperCase();
  if (!cleaned) return '-';
  return unhide ? cleaned : maskVehicleIdNumber(cleaned);
}
