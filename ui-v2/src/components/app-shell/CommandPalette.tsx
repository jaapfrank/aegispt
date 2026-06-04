import { useEffect, useMemo, useRef, useState } from 'react';
import type { KeyboardEvent as ReactKeyboardEvent } from 'react';
import { Command, CornerDownLeft } from 'lucide-react';
import { useI18n } from '../../i18n';
import type { CommandPaletteItem, ToastTone } from './types';
import { cn } from './utils';

export default function CommandPalette({
  items,
  onClose,
  onNavigate,
  onNotify,
}: {
  items: CommandPaletteItem[];
  onClose: () => void;
  onNavigate: (target: string) => void;
  onNotify: (tone: ToastTone, title: string, detail: string) => void;
}) {
  const { t } = useI18n();
  const inputRef = useRef<HTMLInputElement | null>(null);
  const [query, setQuery] = useState('');
  const [activeIndex, setActiveIndex] = useState(0);
  const filteredItems = useMemo(() => filterCommandItems(items, query), [items, query]);
  const activeItem = filteredItems[activeIndex] ?? filteredItems[0] ?? null;
  const listboxId = 'command-palette-listbox';
  const activeDescendantId = activeItem ? `command-item-${activeItem.id}` : undefined;

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  useEffect(() => {
    setActiveIndex(0);
  }, [query]);

  function selectItem(item: CommandPaletteItem | null) {
    if (!item) return;
    item.action?.();
    if (item.to) {
      onNavigate(item.to);
    }
    onNotify('info', item.label, item.detail);
    onClose();
  }

  function handleKeyDown(event: ReactKeyboardEvent<HTMLInputElement>) {
    if (event.key === 'Escape') {
      event.preventDefault();
      onClose();
      return;
    }
    if (event.key === 'ArrowDown') {
      event.preventDefault();
      setActiveIndex((current) => Math.min(filteredItems.length - 1, current + 1));
      return;
    }
    if (event.key === 'ArrowUp') {
      event.preventDefault();
      setActiveIndex((current) => Math.max(0, current - 1));
      return;
    }
    if (event.key === 'Enter') {
      event.preventDefault();
      selectItem(activeItem);
    }
  }

  return (
    <div className="command-palette-overlay" role="presentation" onMouseDown={onClose}>
      <section
        className="command-palette"
        role="dialog"
        aria-modal="true"
        aria-label={t('command.palette')}
        onMouseDown={(event) => event.stopPropagation()}
      >
        <div className="flex items-center gap-3 border-b border-border px-4 py-3">
          <Command size={16} className="text-cyan" />
          <input
            ref={inputRef}
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            onKeyDown={handleKeyDown}
            className="h-10 min-w-0 flex-1 bg-transparent text-[1rem] text-text outline-none placeholder:text-muted"
            placeholder={t('command.searchPlaceholder')}
            aria-label={t('command.searchLabel')}
            role="combobox"
            aria-expanded="true"
            aria-autocomplete="list"
            aria-controls={listboxId}
            aria-activedescendant={activeDescendantId}
          />
          <button
            type="button"
            onClick={onClose}
            className="rounded-md border border-border bg-surface/60 px-2 py-1 text-[0.85rem] font-semibold text-muted transition-colors hover:text-text"
          >
            Esc
          </button>
        </div>

        <div className="max-h-[min(34rem,70vh)] overflow-y-auto p-2">
          {filteredItems.length === 0 ? (
            <div className="rounded-lg border border-dashed border-border bg-bg/35 p-6 text-center">
              <p className="text-[1rem] font-semibold text-text">{t('command.noCommand')}</p>
              <p className="mt-1 text-[0.925rem] text-muted">{t('command.noCommandHint')}</p>
            </div>
          ) : (
            <div id={listboxId} className="space-y-1" role="listbox" aria-label={t('command.resultsLabel')}>
              {filteredItems.map((item, index) => (
                <button
                  key={item.id}
                  id={`command-item-${item.id}`}
                  type="button"
                  role="option"
                  aria-selected={index === activeIndex}
                  onMouseEnter={() => setActiveIndex(index)}
                  onClick={() => selectItem(item)}
                  className={cn(
                    'command-palette-item flex w-full items-center justify-between gap-3 rounded-lg px-3 py-2 text-left transition-all',
                    index === activeIndex ? 'border-cyan/35 bg-cyan/10 text-text' : 'border-transparent text-muted hover:bg-surface/70 hover:text-text',
                  )}
                >
                  <span className="min-w-0">
                    <span className="block truncate text-[1rem] font-semibold">{item.label}</span>
                    <span className="mt-0.5 block truncate text-[0.85rem] text-muted">{item.detail}</span>
                  </span>
                  <span className="flex shrink-0 items-center gap-2">
                    <span className="rounded-full border border-border bg-bg/50 px-2 py-0.5 text-[0.7rem] font-bold uppercase text-muted">
                      {item.group}
                    </span>
                    {index === activeIndex && <CornerDownLeft size={14} className="text-cyan" aria-hidden="true" />}
                  </span>
                </button>
              ))}
            </div>
          )}
        </div>
      </section>
    </div>
  );
}

function filterCommandItems(items: CommandPaletteItem[], query: string): CommandPaletteItem[] {
  const normalized = query.trim().toLowerCase();
  if (!normalized) return items.slice(0, 14);
  const tokens = normalized.split(/\s+/).filter(Boolean);
  return items
    .map((item) => {
      const haystack = `${item.group} ${item.label} ${item.detail} ${item.keywords}`.toLowerCase();
      const score = tokens.reduce((total, token) => total + (haystack.includes(token) ? 1 : -2), 0);
      return { item, score };
    })
    .filter(({ score }) => score > 0)
    .sort((left, right) => right.score - left.score || left.item.label.localeCompare(right.item.label))
    .slice(0, 14)
    .map(({ item }) => item);
}
