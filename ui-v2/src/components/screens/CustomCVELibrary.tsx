import { FormEvent, useEffect, useState } from 'react';
import { Download, Pencil, Trash2, Upload } from 'lucide-react';
import {
  createCustomVulnerability,
  deleteCustomVulnerability,
  exportCustomVulnerabilities,
  getCustomVulnerabilities,
  importCustomVulnerabilities,
  updateCustomVulnerability,
} from '../../api/client';
import type { CustomVulnerability, CustomVulnerabilityInput, UUID } from '../../api/types';
import { ActionButton, EmptyState, Field, PageHeader, Panel, StatusBadge } from './screenPrimitives';
import { inputClass, triggerJsonDownload } from './screenUtils';

const emptyForm: CustomVulnerabilityInput = {
  custom_id: '',
  title: '',
  description: '',
  severity: 'medium',
  affected_products: [],
  cwe_ids: [],
  status: 'draft',
};

export default function CustomCVELibrary() {
  const [items, setItems] = useState<CustomVulnerability[]>([]);
  const [editingId, setEditingId] = useState<UUID | null>(null);
  const [form, setForm] = useState<CustomVulnerabilityInput>(emptyForm);
  const [importPayload, setImportPayload] = useState('');
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  useEffect(() => {
    void loadLibrary();
  }, []);

  async function loadLibrary() {
    setLoading(true);
    setMessage(null);
    try {
      const payload = await getCustomVulnerabilities();
      setItems(payload.items);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Custom vulnerability library unavailable.');
    } finally {
      setLoading(false);
    }
  }

  async function submitForm(event: FormEvent) {
    event.preventDefault();
    setLoading(true);
    try {
      const normalized = normalizeForm(form);
      if (editingId) {
        await updateCustomVulnerability(editingId, normalized);
        await loadLibrary();
        setMessage('Custom vulnerability updated.');
      } else {
        await createCustomVulnerability(normalized);
        await loadLibrary();
        setMessage('Custom vulnerability created.');
      }
      setForm(emptyForm);
      setEditingId(null);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Custom vulnerability save failed.');
    } finally {
      setLoading(false);
    }
  }

  async function removeItem(id: UUID) {
    setLoading(true);
    try {
      await deleteCustomVulnerability(id);
      await loadLibrary();
      setMessage('Custom vulnerability soft-deleted.');
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Delete failed.');
    } finally {
      setLoading(false);
    }
  }

  async function importItems() {
    if (!importPayload.trim()) {
      setMessage('Paste text before importing.');
      return;
    }
    setLoading(true);
    try {
      const result = await importCustomVulnerabilities(importPayload);
      setImportPayload('');
      await loadLibrary();
      setMessage(`Import completed: ${String(result.imported_count ?? 0)} imported.`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Import failed.');
    } finally {
      setLoading(false);
    }
  }

  async function exportItems() {
    try {
      const payload = await exportCustomVulnerabilities();
      triggerJsonDownload(payload, 'aegispt-custom-vulnerabilities.json');
      setMessage('Custom vulnerability export prepared.');
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Export failed.');
    }
  }

  function editItem(item: CustomVulnerability) {
    setEditingId(item.id);
    setForm({
      custom_id: item.custom_id,
      title: item.title,
      description: item.description,
      severity: item.severity as CustomVulnerabilityInput['severity'],
      affected_products: item.affected_products_json,
      cwe_ids: item.cwe_ids_json,
      reporter: item.reporter,
      status: item.status as CustomVulnerabilityInput['status'],
      linked_nuclei_template_ref: item.linked_nuclei_template_ref,
    });
  }

  return (
    <section className="flex h-full min-h-0 flex-col">
      <PageHeader
        eyebrow="Detection Library"
        title="Custom CVE Library"
        detail="Governed custom vulnerability definitions backed by the existing custom-vulnerabilities API."
        actions={<ActionButton onClick={() => void exportItems()}><Download size={14} />Export</ActionButton>}
      />
      {message && <div className="mb-4 rounded-md border border-cyan/25 bg-cyan/10 px-3 py-2 text-[0.925rem] text-cyan">{message}</div>}

      <div className="grid min-h-0 flex-1 gap-5 xl:grid-cols-[420px_1fr]">
        <div className="space-y-5">
          <Panel title={editingId ? 'Edit Definition' : 'Add Definition'}>
            <form onSubmit={(event) => void submitForm(event)} className="space-y-3">
              <Field label="Custom ID">
                <input className={inputClass} value={form.custom_id ?? ''} onChange={(event) => setForm({ ...form, custom_id: event.target.value })} placeholder="CVE-LOCAL-001" />
              </Field>
              <Field label="Title">
                <input className={inputClass} value={form.title} onChange={(event) => setForm({ ...form, title: event.target.value })} required />
              </Field>
              <Field label="Severity">
                <select className={inputClass} value={form.severity} onChange={(event) => setForm({ ...form, severity: event.target.value as CustomVulnerabilityInput['severity'] })}>
                  {['critical', 'high', 'medium', 'low'].map((value) => <option key={value} value={value} className="bg-surface text-text">{value}</option>)}
                </select>
              </Field>
              <Field label="Affected products">
                <input className={inputClass} value={(form.affected_products ?? []).join(', ')} onChange={(event) => setForm({ ...form, affected_products: splitList(event.target.value) })} placeholder="Product, library, platform" />
              </Field>
              <Field label="Description">
                <textarea className={`${inputClass} min-h-[96px] py-2`} value={form.description} onChange={(event) => setForm({ ...form, description: event.target.value })} required />
              </Field>
              <div className="flex gap-2">
                <ActionButton type="submit" loading={loading} tone="green">{editingId ? 'Update' : 'Add'}</ActionButton>
                {editingId && <ActionButton onClick={() => { setEditingId(null); setForm(emptyForm); }} tone="muted">Cancel</ActionButton>}
              </div>
            </form>
          </Panel>

          <Panel title="Import from Text" detail="Uses the existing plain-text import endpoint without AI assistance.">
            <textarea className={`${inputClass} min-h-[120px] py-2`} value={importPayload} onChange={(event) => setImportPayload(event.target.value)} placeholder="Paste vulnerability notes or exported JSON text" />
            <div className="mt-3">
              <ActionButton onClick={() => void importItems()} loading={loading}><Upload size={14} />Import</ActionButton>
            </div>
          </Panel>
        </div>

        <Panel title="Library" detail={`${items.length} definitions`}>
          {items.length ? (
            <div className="max-h-[72vh] overflow-auto">
              <table className="min-w-[820px] w-full text-left text-[0.925rem]">
                <thead className="sticky top-0 bg-surface text-[0.77rem] uppercase tracking-wider text-muted">
                  <tr>
                    <th className="px-3 py-3">ID</th>
                    <th className="px-3 py-3">Title</th>
                    <th className="px-3 py-3">Severity</th>
                    <th className="px-3 py-3">Affected products</th>
                    <th className="px-3 py-3">Template</th>
                    <th className="px-3 py-3">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((item) => (
                    <tr key={item.id} className="border-t border-border">
                      <td className="px-3 py-3 font-mono text-[0.85rem] text-muted">{item.custom_id}</td>
                      <td className="px-3 py-3 font-semibold text-text">{item.title}</td>
                      <td className="px-3 py-3"><StatusBadge value={item.severity} /></td>
                      <td className="px-3 py-3 text-muted">{item.affected_products_json.join(', ') || 'n/a'}</td>
                      <td className="px-3 py-3 text-muted">{item.linked_nuclei_template_ref ?? String(item.test_coverage.status ?? 'unlinked')}</td>
                      <td className="px-3 py-3">
                        <div className="flex gap-2">
                          <ActionButton onClick={() => editItem(item)} tone="muted"><Pencil size={13} />Edit</ActionButton>
                          <ActionButton onClick={() => void removeItem(item.id)} loading={loading} tone="red"><Trash2 size={13} />Delete</ActionButton>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <EmptyState title="No custom definitions" detail="Add a custom vulnerability definition or import text to populate the library." />
          )}
        </Panel>
      </div>
    </section>
  );
}

function splitList(value: string): string[] {
  return value.split(',').map((item) => item.trim()).filter(Boolean);
}

function normalizeForm(form: CustomVulnerabilityInput): CustomVulnerabilityInput {
  return {
    ...form,
    custom_id: form.custom_id?.trim() || null,
    title: form.title.trim(),
    description: form.description.trim(),
    affected_products: form.affected_products ?? [],
    cwe_ids: form.cwe_ids ?? [],
    status: form.status ?? 'draft',
  };
}
