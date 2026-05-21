import { normalizeLocale, SUPPORTED_LOCALES, useI18n, type TranslationKey } from './index';

export default function LanguageSelector() {
  const { locale, setLocale, t } = useI18n();

  return (
    <label className="inline-flex h-8 shrink-0 items-center gap-2 rounded-md border border-border bg-surface/60 px-2 text-[0.85rem] font-semibold text-muted transition-colors hover:border-cyan/40 hover:text-cyan">
      <span className="sr-only">{t('language.selectorLabel')}</span>
      <select
        aria-label={t('language.selectorLabel')}
        data-testid="language-selector"
        value={locale}
        onChange={(event) => setLocale(normalizeLocale(event.target.value))}
        className="h-full bg-transparent text-current outline-none"
      >
        {SUPPORTED_LOCALES.map((candidate) => (
          <option key={candidate} value={candidate} className="bg-surface text-text">
            {t(`language.${candidate}` as TranslationKey)}
          </option>
        ))}
      </select>
    </label>
  );
}
