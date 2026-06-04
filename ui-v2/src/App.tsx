import { Navigate, Route, Routes } from 'react-router-dom';
import AppShell from './components/app-shell/AppShell';
import CustomCVELibrary from './components/screens/CustomCVELibrary';
import DashboardScreen from './components/screens/Dashboard';
import EvidenceReplay from './components/screens/EvidenceReplay';
import FindingsTheater from './components/screens/FindingsTheater';
import HistoryScreen from './components/screens/History';
import IntakeScreen from './components/screens/IntakeScreen';
import LiveCLIScreen from './components/screens/LiveCLI';
import MissionControl from './components/screens/MissionControl';
import PacksScreen from './components/screens/Packs';
import ProblemsCenter from './components/screens/ProblemsCenter';
import ResearchScreen from './components/screens/Research';
import ReportCenter from './components/screens/ReportCenter';
import SettingsScreen from './components/screens/Settings';
import SurfaceMap from './components/screens/SurfaceMap';
import { I18nProvider } from './i18n';

export default function App() {
  return (
    <I18nProvider>
      <Routes>
        <Route element={<AppShell />}>
          <Route index element={<DashboardScreen />} />
          <Route path="intake" element={<IntakeScreen />} />
          <Route path="mission-control" element={<MissionControl />} />
          <Route path="live-cli" element={<LiveCLIScreen />} />
          <Route path="surface-map" element={<SurfaceMap />} />
          <Route path="evidence" element={<EvidenceReplay />} />
          <Route path="findings" element={<FindingsTheater />} />
          <Route path="reports" element={<ReportCenter />} />
          <Route path="history" element={<HistoryScreen />} />
          <Route path="problems" element={<ProblemsCenter />} />
          <Route path="packs" element={<PacksScreen />} />
          <Route path="cve-library" element={<CustomCVELibrary />} />
          <Route path="research" element={<ResearchScreen />} />
          <Route path="settings" element={<SettingsScreen />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </I18nProvider>
  );
}
