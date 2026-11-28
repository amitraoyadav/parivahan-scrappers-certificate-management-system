import React, { useState } from 'react';
import { AlertCircle, Eye, EyeOff, Save, X } from 'lucide-react';
import type { CertificateRecord, CreateCertificateInput, IdProofType } from '../shared/types';
import {
  ALL_PRESET_MANUFACTURERS,
  COMMON_MANUFACTURERS,
  OTHER_MANUFACTURER_VALUE,
  formatChassisOrEngine,
} from '../shared/vehicleData';
import { api, ApiError } from '../lib/api';

interface MakerEditCertificateModalProps {
  certificate: CertificateRecord | null;
  onClose: () => void;
  onSaved: (updated: CertificateRecord) => void;
}

const ID_PROOF_OPTIONS: Array<{ value: IdProofType; label: string }> = [
  { value: '', label: '-- Not Provided (Optional) --' },
  { value: 'Aadhaar Card', label: 'Aadhaar Card' },
  { value: 'PAN Card', label: 'PAN Card' },
  { value: 'Driving License', label: 'Driving License' },
  { value: 'Passport', label: 'Passport' },
  { value: 'Voter ID', label: 'Voter ID' },
];

export const MakerEditCertificateModal: React.FC<MakerEditCertificateModalProps> = ({
  certificate,
  onClose,
  onSaved,
}) => {
  const initialMake = certificate?.make ?? '';
  const initialIsPreset = ALL_PRESET_MANUFACTURERS.includes(initialMake);

  const [issueDate, setIssueDate] = useState(certificate?.issueDate ?? '');
  const [handoverDate, setHandoverDate] = useState(certificate?.handoverDate ?? '');
  const [ownerName, setOwnerName] = useState(certificate?.ownerName ?? '');
  const [ownerAddress, setOwnerAddress] = useState(certificate?.ownerAddress ?? '');
  const [idProofType, setIdProofType] = useState<IdProofType>(certificate?.idProofType ?? '');
  const [idProofNumber, setIdProofNumber] = useState(certificate?.idProofNumber ?? '');
  const [vehicleRegNumber, setVehicleRegNumber] = useState(certificate?.vehicleRegNumber ?? '');
  const [selectedMakeOption, setSelectedMakeOption] = useState(
    initialIsPreset ? initialMake : initialMake ? OTHER_MANUFACTURER_VALUE : ''
  );
  const [customMake, setCustomMake] = useState(initialIsPreset ? '' : initialMake);
  const [model, setModel] = useState(certificate?.model ?? '');
  const [manufactureYear, setManufactureYear] = useState(certificate?.manufactureYear ?? 2012);
  const [chassisNumber, setChassisNumber] = useState(certificate?.chassisNumber ?? '');
  const [engineNumber, setEngineNumber] = useState(certificate?.engineNumber ?? '');
  const [unhideChassisEngine, setUnhideChassisEngine] = useState(
    certificate?.unhideChassisEngine === true
  );
  const [remarks, setRemarks] = useState(certificate?.remarks ?? '');
  const [reason, setReason] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!certificate) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSaving(true);
    try {
      const effectiveMake =
        selectedMakeOption === OTHER_MANUFACTURER_VALUE
          ? customMake.trim()
          : selectedMakeOption.trim();

      if (
        !effectiveMake ||
        effectiveMake.length < 2 ||
        effectiveMake === OTHER_MANUFACTURER_VALUE ||
        (selectedMakeOption === OTHER_MANUFACTURER_VALUE &&
          effectiveMake.toLowerCase() === 'other')
      ) {
        setError('Please enter a valid manufacturer name (at least 2 characters).');
        return;
      }

      const cleanedAddress = ownerAddress.trim();
      const cleanedIdNumber = idProofNumber.trim();
      const cleanedIdType: IdProofType = cleanedIdNumber ? idProofType : '';

      const updates: Partial<CreateCertificateInput> = {
        issueDate,
        handoverDate,
        ownerName,
        ownerAddress: cleanedAddress,
        idProofType: cleanedIdType,
        idProofNumber: cleanedIdNumber,
        vehicleRegNumber,
        make: effectiveMake,
        model,
        manufactureYear,
        chassisNumber,
        engineNumber,
        unhideChassisEngine,
        remarks,
      };
      const res = await api.editCertificateMaker(certificate.id, {
        updates,
        reason: reason.trim() || undefined,
      });
      onSaved(res.certificate);
      onClose();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Unable to save certificate changes.');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 bg-slate-900/60 flex items-center justify-center p-4 overflow-y-auto"
      role="dialog"
      aria-modal="true"
      aria-label="Edit Certificate"
    >
      <div className="bg-white rounded-xl border border-slate-200 w-full max-w-2xl max-h-[92vh] overflow-y-auto shadow-xl">
        <div className="px-6 py-4 border-b border-slate-200 flex items-center justify-between bg-slate-50 sticky top-0 z-10">
          <div>
            <h3 className="font-display font-bold text-base text-[#0B1F3A]">
              Edit Certificate Details
            </h3>
            <p className="text-xs font-mono text-slate-500 mt-0.5 tabular-nums">
              {certificate.certificateNumber} · {certificate.scrappingRegNumber} (Number Preserved)
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-500 hover:bg-slate-200 cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-6 space-y-5">
          {error && (
            <div className="p-3.5 rounded-lg bg-red-50 border border-red-200 text-red-800 text-sm flex items-start gap-2">
              <AlertCircle className="w-4 h-4 shrink-0 mt-0.5 text-red-600" />
              <span>{error}</span>
            </div>
          )}

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-slate-700 mb-1">
                Issue Date <span className="text-red-600">*</span>
              </label>
              <input
                type="date"
                required
                value={issueDate}
                onChange={(e) => setIssueDate(e.target.value)}
                className="w-full px-3 py-2 rounded-lg border border-slate-300 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-[#059669]"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-700 mb-1">
                Vehicle Handover Date <span className="text-red-600">*</span>
              </label>
              <input
                type="date"
                required
                value={handoverDate}
                onChange={(e) => setHandoverDate(e.target.value)}
                className="w-full px-3 py-2 rounded-lg border border-slate-300 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-[#059669]"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-700 mb-1">
                Owner Full Name <span className="text-red-600">*</span>
              </label>
              <input
                type="text"
                required
                minLength={2}
                value={ownerName}
                onChange={(e) => setOwnerName(e.target.value)}
                className="w-full px-3 py-2 rounded-lg border border-slate-300 text-sm focus:outline-none focus:ring-2 focus:ring-[#059669]"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-700 mb-1">
                RC Number (Vehicle No.) <span className="text-red-600">*</span>
              </label>
              <input
                type="text"
                required
                minLength={4}
                value={vehicleRegNumber}
                onChange={(e) => setVehicleRegNumber(e.target.value.toUpperCase())}
                className="w-full px-3 py-2 rounded-lg border border-slate-300 text-sm font-mono uppercase focus:outline-none focus:ring-2 focus:ring-[#059669]"
              />
            </div>

            <div className="sm:col-span-2">
              <label className="block text-xs font-medium text-slate-700 mb-1">
                Residential Address <span className="text-slate-400 font-normal">(Optional)</span>
              </label>
              <input
                type="text"
                value={ownerAddress}
                onChange={(e) => setOwnerAddress(e.target.value)}
                className="w-full px-3 py-2 rounded-lg border border-slate-300 text-sm focus:outline-none focus:ring-2 focus:ring-[#059669]"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-700 mb-1">
                ID Proof Type <span className="text-slate-400 font-normal">(Optional)</span>
              </label>
              <select
                value={idProofType}
                onChange={(e) => setIdProofType(e.target.value as IdProofType)}
                className="w-full px-3 py-2 rounded-lg border border-slate-300 text-sm bg-white focus:outline-none focus:ring-2 focus:ring-[#059669]"
              >
                {ID_PROOF_OPTIONS.map((opt) => (
                  <option key={opt.value || 'none'} value={opt.value}>
                    {opt.label}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-700 mb-1">
                ID Proof Number <span className="text-slate-400 font-normal">(Optional)</span>
              </label>
              <input
                type="text"
                value={idProofNumber}
                onChange={(e) => setIdProofNumber(e.target.value.toUpperCase())}
                className="w-full px-3 py-2 rounded-lg border border-slate-300 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-[#059669]"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-700 mb-1">
                Make / Manufacturer <span className="text-red-600">*</span>
              </label>
              <select
                required
                value={selectedMakeOption}
                onChange={(e) => setSelectedMakeOption(e.target.value)}
                className="w-full px-3 py-2 rounded-lg border border-slate-300 text-sm bg-white focus:outline-none focus:ring-2 focus:ring-[#059669]"
              >
                <option value="">-- Select Manufacturer --</option>
                {COMMON_MANUFACTURERS.map((brand) => (
                  <option key={brand} value={brand}>
                    {brand}
                  </option>
                ))}
                <option value={OTHER_MANUFACTURER_VALUE}>Other</option>
              </select>
              {selectedMakeOption === OTHER_MANUFACTURER_VALUE && (
                <div className="mt-2">
                  <label
                    htmlFor="maker-edit-custom-manufacturer"
                    className="block text-xs font-medium text-slate-700 mb-1"
                  >
                    Enter Manufacturer Name <span className="text-red-600">*</span>
                  </label>
                  <input
                    id="maker-edit-custom-manufacturer"
                    name="customManufacturerName"
                    type="text"
                    required
                    minLength={2}
                    value={customMake}
                    onChange={(e) => setCustomMake(e.target.value)}
                    placeholder="Enter Manufacturer Name"
                    className="w-full px-3 py-2 rounded-lg border border-slate-300 text-sm focus:outline-none focus:ring-2 focus:ring-[#059669]"
                  />
                </div>
              )}
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-700 mb-1">
                Model / Variant <span className="text-red-600">*</span>
              </label>
              <input
                type="text"
                required
                value={model}
                onChange={(e) => setModel(e.target.value)}
                className="w-full px-3 py-2 rounded-lg border border-slate-300 text-sm focus:outline-none focus:ring-2 focus:ring-[#059669]"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-700 mb-1">
                Year of Manufacture <span className="text-red-600">*</span>
              </label>
              <input
                type="number"
                required
                min={1950}
                max={new Date().getFullYear() + 1}
                value={manufactureYear}
                onChange={(e) => setManufactureYear(Number(e.target.value))}
                className="w-full px-3 py-2 rounded-lg border border-slate-300 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-[#059669]"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-700 mb-1">
                Chassis Number (VIN) <span className="text-red-600">*</span>
              </label>
              <input
                type="text"
                required
                minLength={6}
                value={chassisNumber}
                onChange={(e) => setChassisNumber(e.target.value.toUpperCase())}
                className="w-full px-3 py-2 rounded-lg border border-slate-300 text-sm font-mono uppercase focus:outline-none focus:ring-2 focus:ring-[#059669]"
              />
              {chassisNumber.trim().length > 0 && (
                <p className="mt-1 text-[11px] font-mono text-slate-500">
                  Prints: {formatChassisOrEngine(chassisNumber, unhideChassisEngine)}
                </p>
              )}
            </div>

            <div className="sm:col-span-2">
              <label className="block text-xs font-medium text-slate-700 mb-1">
                Engine Number <span className="text-red-600">*</span>
              </label>
              <input
                type="text"
                required
                minLength={5}
                value={engineNumber}
                onChange={(e) => setEngineNumber(e.target.value.toUpperCase())}
                className="w-full px-3 py-2 rounded-lg border border-slate-300 text-sm font-mono uppercase focus:outline-none focus:ring-2 focus:ring-[#059669]"
              />
              {engineNumber.trim().length > 0 && (
                <p className="mt-1 text-[11px] font-mono text-slate-500">
                  Prints: {formatChassisOrEngine(engineNumber, unhideChassisEngine)}
                </p>
              )}
            </div>

            <div className="sm:col-span-2">
              <label className="flex items-center gap-2.5 p-3 rounded-lg border border-slate-200 bg-slate-50 cursor-pointer text-xs">
                <input
                  type="checkbox"
                  checked={unhideChassisEngine}
                  onChange={(e) => setUnhideChassisEngine(e.target.checked)}
                  className="h-4 w-4 rounded border-slate-300 text-[#059669] focus:ring-[#059669]"
                />
                {unhideChassisEngine ? (
                  <Eye className="w-3.5 h-3.5 text-[#059669]" />
                ) : (
                  <EyeOff className="w-3.5 h-3.5 text-slate-500" />
                )}
                <span className="font-medium text-slate-700">
                  Unhide full Chassis &amp; Engine Number on Certificate &amp; PDF
                </span>
              </label>
            </div>

            <div className="sm:col-span-2">
              <label className="block text-xs font-medium text-slate-700 mb-1">
                Remarks / Inspection Notes <span className="text-slate-400 font-normal">(Optional)</span>
              </label>
              <input
                type="text"
                value={remarks}
                onChange={(e) => setRemarks(e.target.value)}
                className="w-full px-3 py-2 rounded-lg border border-slate-300 text-sm focus:outline-none focus:ring-2 focus:ring-[#059669]"
              />
            </div>

            <div className="sm:col-span-2">
              <label className="block text-xs font-medium text-slate-700 mb-1">
                Edit Note <span className="text-slate-400 font-normal">(Optional — recorded in audit log)</span>
              </label>
              <input
                type="text"
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                placeholder="e.g. Corrected spelling of owner name"
                className="w-full px-3 py-2 rounded-lg border border-slate-300 text-sm focus:outline-none focus:ring-2 focus:ring-[#059669]"
              />
            </div>
          </div>

          <p className="text-xs text-slate-500">
            Saving preserves certificate number <span className="font-mono font-semibold">{certificate.certificateNumber}</span>,
            archives version {certificate.version} in audit history, updates the SHA-256 hash, and refreshes the PDF &amp; QR code.
          </p>

          <div className="pt-3 flex items-center justify-end gap-2.5 border-t border-slate-200">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 rounded-lg border border-slate-300 bg-white hover:bg-slate-50 text-sm font-medium text-slate-700 cursor-pointer"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={saving}
              className="inline-flex items-center gap-2 px-5 py-2 rounded-lg bg-[#059669] hover:bg-[#047857] text-white text-sm font-semibold transition-colors disabled:opacity-50 cursor-pointer"
            >
              <Save className="w-4 h-4" />
              {saving ? 'Saving...' : 'Save Changes & Refresh PDF'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
