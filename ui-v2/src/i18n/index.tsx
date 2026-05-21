/* eslint-disable react-refresh/only-export-components */
import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import en from './locales/en.json';
import nl from './locales/nl.json';
import de from './locales/de.json';
import fr from './locales/fr.json';
import { phraseCatalog } from './phraseCatalog';

export const SUPPORTED_LOCALES = ['en', 'nl', 'de', 'fr'] as const;
export type Locale = (typeof SUPPORTED_LOCALES)[number];
export type TranslationKey = keyof typeof en & string;
export type TFunction = (key: TranslationKey, params?: Record<string, string | number>) => string;

const DEFAULT_LOCALE: Locale = 'en';
const LOCALE_STORAGE_KEY = 'aegispt.ui-v2.locale';
const messages: Record<Locale, Record<string, string>> = { en, nl, de, fr };
const textNodeOriginals = new WeakMap<Text, string>();
const attributeOriginals = new WeakMap<Element, Map<string, string>>();
const translatedAttributes = ['aria-label', 'placeholder', 'title'] as const;

type I18nContextValue = {
  locale: Locale;
  setLocale: (locale: Locale) => void;
  t: TFunction;
};

const I18nContext = createContext<I18nContextValue | null>(null);

function normalizeLocale(value: string | null | undefined): Locale {
  if (SUPPORTED_LOCALES.includes(value as Locale)) {
    return value as Locale;
  }
  return DEFAULT_LOCALE;
}

function initialLocale(): Locale {
  if (typeof window === 'undefined') return DEFAULT_LOCALE;
  return normalizeLocale(window.localStorage.getItem(LOCALE_STORAGE_KEY) ?? window.navigator.language.slice(0, 2));
}

export function I18nProvider({ children }: { children: ReactNode }) {
  const [locale, setLocaleState] = useState<Locale>(() => initialLocale());

  useEffect(() => {
    document.documentElement.lang = locale;
    applyPhraseCatalog(locale);
    const observer = new MutationObserver(() => applyPhraseCatalog(locale));
    observer.observe(document.body, {
      childList: true,
      subtree: true,
      characterData: true,
      attributes: true,
      attributeFilter: [...translatedAttributes],
    });
    return () => observer.disconnect();
  }, [locale]);

  const setLocale = useCallback((nextLocale: Locale) => {
    setLocaleState(nextLocale);
    window.localStorage.setItem(LOCALE_STORAGE_KEY, nextLocale);
    document.documentElement.lang = nextLocale;
  }, []);

  const t = useCallback<TFunction>(
    (key, params) => {
      const template = messages[locale][key] ?? messages.en[key] ?? key;
      if (!params) return template;
      return Object.entries(params).reduce(
        (text, [name, value]) => text.split(`{${name}}`).join(String(value)),
        template,
      );
    },
    [locale],
  );

  const value = useMemo(() => ({ locale, setLocale, t }), [locale, setLocale, t]);

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

export function useI18n(): I18nContextValue {
  const context = useContext(I18nContext);
  if (!context) {
    throw new Error('useI18n must be used inside I18nProvider');
  }
  return context;
}

export { normalizeLocale };

function applyPhraseCatalog(locale: Locale) {
  if (typeof document === 'undefined') return;
  translateTextNodes(document.body, locale);
  translateAttributes(document.body, locale);
}

function translateTextNodes(root: HTMLElement, locale: Locale) {
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
    acceptNode(node) {
      if (!node.textContent?.trim()) return NodeFilter.FILTER_REJECT;
      const parent = node.parentElement;
      if (!parent || shouldIgnoreElement(parent)) return NodeFilter.FILTER_REJECT;
      return NodeFilter.FILTER_ACCEPT;
    },
  });

  const nodes: Text[] = [];
  while (walker.nextNode()) {
    nodes.push(walker.currentNode as Text);
  }

  for (const node of nodes) {
    const current = node.textContent ?? '';
    const original = textNodeOriginals.get(node) ?? current;
    if (!textNodeOriginals.has(node) && !hasCatalogPhrase(original)) continue;
    if (!textNodeOriginals.has(node)) textNodeOriginals.set(node, original);
    const next = translatePhrase(original, locale);
    if (node.textContent !== next) {
      node.textContent = next;
    }
  }
}

function translateAttributes(root: HTMLElement, locale: Locale) {
  const elements = [root, ...Array.from(root.querySelectorAll<HTMLElement>('*'))];
  for (const element of elements) {
    if (shouldIgnoreElement(element)) continue;
    let originals = attributeOriginals.get(element);
    for (const attr of translatedAttributes) {
      const current = element.getAttribute(attr);
      if (!current?.trim()) continue;
      const existingOriginal = originals?.get(attr);
      if (!existingOriginal && !hasCatalogPhrase(current)) continue;
      if (!originals) {
        originals = new Map();
        attributeOriginals.set(element, originals);
      }
      if (!originals.has(attr)) {
        originals.set(attr, current);
      }
      const original = originals.get(attr) ?? current;
      const next = translatePhrase(original, locale);
      if (current !== next) {
        element.setAttribute(attr, next);
      }
    }
  }
}

function translatePhrase(value: string, locale: Locale): string {
  if (locale === 'en') return value;
  const trimmed = value.trim();
  const translated = phraseCatalog[locale][trimmed];
  if (!translated) return value;
  const leading = value.match(/^\s*/)?.[0] ?? '';
  const trailing = value.match(/\s*$/)?.[0] ?? '';
  return `${leading}${translated}${trailing}`;
}

function hasCatalogPhrase(value: string): boolean {
  const trimmed = value.trim();
  return Boolean(phraseCatalog.nl[trimmed] || phraseCatalog.de[trimmed] || phraseCatalog.fr[trimmed]);
}

function shouldIgnoreElement(element: Element): boolean {
  if (element.closest('[data-i18n-ignore]')) return true;
  return ['SCRIPT', 'STYLE', 'PRE', 'CODE', 'TEXTAREA'].includes(element.tagName);
}
