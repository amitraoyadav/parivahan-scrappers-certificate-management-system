import React, { useState } from 'react';
import { AlertCircle, ShieldAlert, X } from 'lucide-react';
import type { CertificateRecord, CreateCertificateInput } from '../shared/types';
import {
  ALL_PRESET_MANUFACTURERS,
  OTHER_MANUFACTURER_VALUE,
  VEHICLE_MANUFACTURER_GROUPS,
} from '../shared/vehicleData';
import { api, ApiError } from '../lib/api';

export type ProtectedActionMode = 'edit' | 'cancel' | 'soft_delete' | 'permanent_delete' | 'restore';

interface ProtectedActionModalProps {
  certificate: CertificateRecord | null;
  mode: ProtectedActionMode | null;
  onClose: () => void;
  onSuccess: () => Promise<void>;
}

export const ProtectedActionModal: React.FC<ProtectedActionModalProps> = ({
  certificate,
  mode,
  onClose,
  onSuccess,
}) => {
  const [protectedPassword, setProtectedPassword] = useState('');
  const [reason, setReason] = useState('');
  const [confirmPhrase, setConfirmPhrase] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const initialMake = certificate?.make ?? '';
  const initialIsPreset = ALL_PRESET_MANUFACTURERS.includes(initialMake);

  // Editable fields for Protected Edit mode
  const [ownerName, setOwnerName] = useState(certificate?.ownerName ?? '');
  const [ownerAddress, setOwnerAddress] = useState(certificate?.ownerAddress ?? '');
  const [vehicleRegNumber, setVehicleRegNumber] = useState(certificate?.vehicleRegNumber ?? '');
  const [selectedMakeOption, setSelectedMakeOption] = useState(
    initialIsPreset ? initialMake : initialMake ? OTHER_MANUFACTURER_VALUE : ''
  );
  const [customMake, setCustomMake] = useState(initialIsPreset ? '' : initialMake);
  const [model, setModel] = useState(certificate?.model ?? '');
  const [chassisNumber, setChassisNumber] = useState(certificate?.chassisNumber ?? '');
  const [engineNumber, setEngineNumber] = useState(certificate?.engineNumber ?? '');
  const [unhideChassisEngine, setUnhideChassisEngine] = useState(
    certificate?.unhideChassisEngine === true
  );
  const [rtoAuthority, setRtoAuthority] = useState(certificate?.rtoAuthority ?? '');
  const [remarks, setRemarks] = useState(certificate?.remarks ?? '');

  if (!certificate || !mode) return null;

  const titles: Record<ProtectedActionMode, string> = {
    edit: 'Protected Certificate Edit',
    cancel: 'Protected Certificate Cancellation',
    soft_delete: 'Protected Soft Deletion',
    permanent_delete: 'Permanent Certificate Deletion',
    restore: 'Restore Soft-Deleted Certificate',
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSubmitting(true);

    try {
      if (mode === 'edit') {
        const effectiveMake =
          selectedMakeOption === OTHER_MANUFACTURER_VALUE ? customMake.trim() : selectedMakeOption;
        const updates: Partial<CreateCertificateInput> = {
          ownerName,
          ownerAddress,
          vehicleRegNumber,
          make: effectiveMake,
          model,
          chassisNumber,
          engineNumber,
          unhideChassisEngine,
          rtoAuthority,
          remarks,
        };
        await api.editCertificateProtected(certificate.id, {
          protectedPassword,
          reason,
          updates,
        });
      } else if (mode === 'cancel') {
        await api.cancelCertificateProtected(certificate.id, {
          protectedPassword,
          reason,
        });
      } else if (mode === 'soft_delete') {
        await api.deleteCertificateProtected(certificate.id, {
          deletePassword: protectedPassword,
          reason,
          permanent: false,
        });
      } else if (mode === 'permanent_delete') {
        await api.deleteCertificateProtected(certificate.id, {
          deletePassword: protectedPassword,
          reason,
          permanent: true,
          confirmPhrase,
        });
      } else if (mode === 'restore') {
        await api.restoreCertificateProtected(certificate.id, {
          protectedPassword,
          reason,
        });
      }

      await onSuccess();
      onClose();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Protected operation failed.');
    } finally {
      setSubmitting(false);
    }
  };

  const isDestructive = mode === 'cancel' || mode === 'soft_delete' || mode === 'permanent_delete';

  return (
    <div
      className="fixed inset-0 z-50 bg-slate-900/60 flex items-center justify-center p-4 overflow-y-auto"
      role="dialog"
      aria-modal="true"
    >
      <div className="bg-white rounded-xl border border-slate-200 w-full max-w-xl max-h-[92vh] overflow-y-auto shadow-xl">
        <div className="px-6 py-4 border-b border-slate-200 flex items-center justify-between bg-slate-50">
          <div className="flex items-center gap-2.5">
            <ShieldAlert
              className={`w-5 h-5 ${isDestructive ? 'text-red-600' : 'text-[#0B1F3A]'}`}
            />
            <div>
              <h3 className="font-display font-bold text-base text-[#0B1F3A]">{titles[mode]}</h3>
              <p className="text-xs font-mono text-slate-500">
                {certificate.certificateNumber} · {certificate.vehicleRegNumber}
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-500 hover:bg-slate-200 cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          {error && (
            <div className="p-3.5 rounded-lg bg-red-50 border border-red-200 text-red-800 text-sm flex items-start gap-2">
              <AlertCircle className="w-4 h-4 shrink-0 mt-0.5 text-red-600" />
              <span>{error}</span>
            </div>
          )}

          {mode === 'edit' && (
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5 pb-4 border-b border-slate-200">
              <div>
                <label className="block text-xs font-medium text-slate-700 mb-1">Owner Name</label>
                <input
                  type="text"
                  required
                  value={ownerName}
                  onChange={(e) => setOwnerName(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg border border-slate-300 text-sm"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-700 mb-1">
                  RC Number (Vehicle No.)
                </label>
                <input
                  type="text"
                  required
                  value={vehicleRegNumber}
                  onChange={(e) => setVehicleRegNumber(e.target.value.toUpperCase())}
                  className="w-full px-3 py-2 rounded-lg border border-slate-300 text-sm font-mono"
                />
              </div>
              <div className="sm:col-span-2">
                <label className="block text-xs font-medium text-slate-700 mb-1">
                  Owner Address (Optional)
                </label>
                <input
                  type="text"
                  value={ownerAddress}
                  onChange={(e) => setOwnerAddress(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg border border-slate-300 text-sm"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-700 mb-1">
                  Make / Manufacturer
                </label>
                <select
                  required
                  value={selectedMakeOption}
                  onChange={(e) => setSelectedMakeOption(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg border border-slate-300 text-sm bg-white"
                >
                  <option value="">-- Select Manufacturer --</option>
                  {VEHICLE_MANUFACTURER_GROUPS.map((group) => (
                    <optgroup key={group.category} label={group.category}>
                      {group.brands.map((brand) => (
                        <option key={brand} value={brand}>
                          {brand}
                        </option>
                      ))}
                    </optgroup>
                  ))}
                  <optgroup label="Other">
                    <option value={OTHER_MANUFACTURER_VALUE}>Other (Type Manually)</option>
                  </optgroup>
                </select>
                {selectedMakeOption === OTHER_MANUFACTURER_VALUE && (
                  <input
                    type="text"
                    required
                    value={customMake}
                    onChange={(e) => setCustomMake(e.target.value)}
                    placeholder="Enter manufacturer"
                    className="mt-2 w-full px-3 py-2 rounded-lg border border-slate-300 text-sm"
                  />
                )}
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-700 mb-1">Model</label>
                <input
                  type="text"
                  required
                  value={model}
                  onChange={(e) => setModel(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg border border-slate-300 text-sm"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-700 mb-1">Chassis No.</label>
                <input
                  type="text"
                  required
                  value={chassisNumber}
                  onChange={(e) => setChassisNumber(e.target.value.toUpperCase())}
                  className="w-full px-3 py-2 rounded-lg border border-slate-300 text-sm font-mono"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-700 mb-1">Engine No.</label>
                <input
                  type="text"
                  required
                  value={engineNumber}
                  onChange={(e) => setEngineNumber(e.target.value.toUpperCase())}
                  className="w-full px-3 py-2 rounded-lg border border-slate-300 text-sm font-mono"
                />
              </div>
              <div className="sm:col-span-2">
                <label className="inline-flex items-center gap-2 text-xs font-medium text-slate-700 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={unhideChassisEngine}
                    onChange={(e) => setUnhideChassisEngine(e.target.checked)}
                    className="h-4 w-4 rounded border-slate-300 text-[#059669] focus:ring-[#059669]"
                  />
                  <span>Unhide full Chassis &amp; Engine Number on Certificate &amp; PDF</span>
                </label>
              </div>
              <div className="sm:col-span-2">
                <label className="block text-xs font-medium text-slate-700 mb-1">RTO Authority</label>
                <input
                  type="text"
                  required
                  value={rtoAuthority}
                  onChange={(e) => setRtoAuthority(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg border border-slate-300 text-sm"
                />
              </div>
              <div className="sm:col-span-2">
                <label className="block text-xs font-medium text-slate-700 mb-1">Remarks</label>
                <input
                  type="text"
                  value={remarks}
                  onChange={(e) => setRemarks(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg border border-slate-300 text-sm"
                />
              </div>
              <p className="sm:col-span-2 text-xs text-slate-500">
                Editing archives version {certificate.version} in immutable history, updates the
                canonical SHA-256 digest, and regenerates the QR verification token.
              </p>
            </div>
          )}

          {mode === 'cancel' && (
            <div className="p-3.5 rounded-lg bg-amber-50 border border-amber-200 text-xs text-amber-950">
              Cancelling permanently marks this certificate as CANCELLED on public QR verification.
              The certificate number ({certificate.certificateNumber}) and registration number (
              {certificate.scrappingRegNumber}) remain permanently reserved and will never be reused.
            </div>
          )}

          {mode === 'soft_delete' && (
            <div className="p-3.5 rounded-lg bg-amber-50 border border-amber-200 text-xs text-amber-950">
              Soft deletion hides this record from Maker views and public verification while keeping
              it recoverable by Main Core Admin. Reserved numbers are never reused.
            </div>
          )}

          {mode === 'permanent_delete' && (
            <div className="p-3.5 rounded-lg bg-red-50 border border-red-200 text-xs text-red-900 space-y-2">
              <p className="font-semibold">
                Irreversible Operation — Automatic Pre-Delete Safety Backup Enabled
              </p>
              <p>
                A verified safety snapshot will be created before permanently deleting this record.
                Its certificate and scrapping numbers remain permanently reserved to prevent reuse.
              </p>
            </div>
          )}

          <div>
            <label className="block text-xs font-medium text-slate-700 mb-1.5">
              Mandatory Audit Reason <span className="text-red-600">*</span>
            </label>
            <textarea
              required
              minLength={5}
              rows={2}
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="Provide detailed justification recorded in immutable audit logs..."
              className="w-full px-3 py-2 rounded-lg border border-slate-300 text-sm focus:outline-none focus:ring-2 focus:ring-[#059669]"
            />
          </div>

          {mode === 'permanent_delete' && (
            <div>
              <label className="block text-xs font-medium text-slate-700 mb-1.5">
                Type <span className="font-mono font-bold text-red-700">PERMANENT DELETE</span> to
                confirm
              </label>
              <input
                type="text"
                required
                value={confirmPhrase}
                onChange={(e) => setConfirmPhrase(e.target.value)}
                placeholder="PERMANENT DELETE"
                className="w-full px-3 py-2 rounded-lg border border-red-300 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-red-500"
              />
            </div>
          )}

          <div>
            <label className="block text-xs font-medium text-slate-700 mb-1.5">
              {mode === 'soft_delete' || mode === 'permanent_delete'
                ? 'Protected Deletion Password'
                : 'Protected Action Password'}{' '}
              <span className="text-red-600">*</span>
            </label>
            <input
              type="password"
              required
              value={protectedPassword}
              onChange={(e) => setProtectedPassword(e.target.value)}
              placeholder="Enter separate protected authorization password"
              className="w-full px-3 py-2 rounded-lg border border-slate-300 text-sm focus:outline-none focus:ring-2 focus:ring-[#059669]"
            />
          </div>

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
              disabled={submitting}
              className={`px-5 py-2 rounded-lg text-sm font-semibold text-white transition-colors disabled:opacity-50 cursor-pointer ${
                isDestructive
                  ? 'bg-red-700 hover:bg-red-800'
                  : 'bg-[#0B1F3A] hover:bg-[#132f57]'
              }`}
            >
              {submitting ? 'Authorizing...' : 'Confirm Authorized Action'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
