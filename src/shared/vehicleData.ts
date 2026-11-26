export interface ManufacturerGroup {
  category: string;
  brands: string[];
}

export const VEHICLE_MANUFACTURER_GROUPS: ManufacturerGroup[] = [
  {
    category: 'Bikes / Motorcycles',
    brands: [
      'Hero MotoCorp',
      'Honda Motorcycle',
      'Bajaj Auto',
      'TVS Motor',
      'Royal Enfield',
      'Yamaha Motor',
      'Suzuki Motorcycle',
      'Hero Honda',
      'KTM',
      'Jawa / Yezdi',
      'Kawasaki',
      'Mahindra Two Wheelers',
      'Benelli',
      'Triumph',
      'BMW Motorrad',
      'Harley-Davidson',
      'Revolt Motors',
    ],
  },
  {
    category: 'Scooty / Scooters',
    brands: [
      'Honda Scooter (Activa / Dio)',
      'TVS Scooty / Jupiter / NTorq',
      'Suzuki Access / Burgman',
      'Hero Pleasure / Destini / Maestro',
      'Yamaha Fascino / RayZR',
      'Bajaj Chetak',
      'Vespa',
      'Aprilia',
      'Kinetic Honda',
      'LML Vespa',
      'Ather Energy',
      'Ola Electric',
      'Hero Vida',
      'Ampere Electric',
      'Okinawa Electric',
      'Simple Energy',
    ],
  },
  {
    category: 'Cars & SUVs',
    brands: [
      'Maruti Suzuki',
      'Hyundai',
      'Tata Motors',
      'Mahindra',
      'Honda Cars',
      'Toyota',
      'Kia',
      'Volkswagen',
      'Skoda',
      'Renault',
      'Nissan',
      'Ford',
      'Chevrolet',
      'Fiat',
      'MG Motor',
      'Jeep',
      'Citroen',
      'Mercedes-Benz',
      'BMW',
      'Audi',
      'Volvo',
      'Hindustan Motors',
      'Daewoo',
      'Mitsubishi',
    ],
  },
  {
    category: 'Commercial / Three-Wheeler / Tractor',
    brands: [
      'Ashok Leyland',
      'Eicher Motors',
      'SML Isuzu',
      'Force Motors',
      'Piaggio Ape',
      'Atul Auto',
      'Swaraj',
      'Sonalika',
      'Escorts / Farmtrac',
      'John Deere',
      'Massey Ferguson (TAFE)',
      'New Holland',
    ],
  },
];

export const ALL_PRESET_MANUFACTURERS: string[] = VEHICLE_MANUFACTURER_GROUPS.flatMap(
  (g) => g.brands
);

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
