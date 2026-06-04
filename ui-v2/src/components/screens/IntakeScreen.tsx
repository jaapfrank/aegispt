import Intake from '../Intake';
import { useI18n } from '../../i18n';

export default function IntakeScreen() {
  const { t } = useI18n();
  return (
    <div className="h-full w-full flex flex-col">
      <div className="shrink-0 mb-4">
        <h1 className="text-2xl font-semibold">{t('intake.title')}</h1>
        <p className="text-muted text-[1rem] mt-1">{t('intake.subtitle')}</p>
      </div>
      <div className="flex-1 min-h-0">
        <Intake />
      </div>
    </div>
  );
}
