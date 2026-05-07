import React, { useState, useEffect } from 'react';
import {
  Activity,
  Crosshair,
  ShieldAlert,
  FileText,
  History,
  Box,
  Settings,
  ChevronDown,
  Plus,
  MonitorPlay
} from 'lucide-react';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';
import Intake from './components/Intake';
import CinemaMode from './components/CinemaMode';

// Utility for cleaner tailwind classes
function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export default function App() {
  const [activeTab, setActiveTab] = useState('mission-control');
  const [isRunning] = useState(true);
  const [isCinemaModeOpen, setIsCinemaModeOpen] = useState(false);

  // Simulated living system effect
  useEffect(() => {
    const interval = setInterval(() => {
      // Logic for random flashes/updates could go here
    }, 3000);
    return () => clearInterval(interval);
  }, []);

  return (
    <>
    {isCinemaModeOpen && <CinemaMode onClose={() => setIsCinemaModeOpen(false)} />}
    <div className="flex h-screen w-full flex-col overflow-hidden bg-bg text-text font-sans">

      {/* TOPBAR (48px) */}
      <header className="flex h-[48px] shrink-0 items-center justify-between border-b border-border bg-[rgba(5,9,18,0.97)] px-4 z-50">

        {/* Left: Branding & Engagement */}
        <div className="flex h-full items-center gap-4">
          <div className="flex items-center gap-2 pr-4 border-r border-border h-full">
            <div className="flex h-[22px] w-[22px] items-center justify-center rounded-[5px] bg-cyan text-[11px] font-extrabold text-[#04080f]">
              ◈
            </div>
            <span className="text-[13px] font-bold text-cyan tracking-wide">AegisPT</span>
          </div>

          <button className="flex items-center gap-2 text-[13px] font-medium text-text hover:text-cyan transition-colors">
            <span>Customer API v1</span>
            <ChevronDown size={14} className="text-muted" />
          </button>
        </div>

        {/* Right: Living Status & Actor */}
        <div className="flex h-full items-center gap-6">
          {isRunning && (
            <div className="flex items-center gap-2 rounded-full bg-cyan/10 px-3 py-1 border border-cyan/20">
              <div className="h-[7px] w-[7px] rounded-full bg-cyan animate-pulse-fast shadow-[0_0_8px_rgba(94,207,255,0.8)]" />
              <span className="text-[12px] font-medium text-cyan">1 run active</span>
            </div>
          )}

          <div className="flex h-full items-center gap-4 pl-6 border-l border-border">
            <button className="text-muted hover:text-text transition-colors">
              <Settings size={16} />
            </button>
            <button className="flex items-center gap-2 text-[13px] font-medium text-text hover:text-cyan transition-colors">
              <span>operator-ui</span>
              <ChevronDown size={14} className="text-muted" />
            </button>
          </div>
        </div>
      </header>

      {/* WORKSPACE */}
      <div className="flex flex-1 overflow-hidden">

        {/* SIDEBAR (180px) */}
        <aside className="w-[180px] shrink-0 border-r border-border bg-bg flex flex-col pt-4 overflow-y-auto">

          <div className="px-3 mb-6">
            <button className="w-full flex items-center justify-center gap-2 rounded-md border border-cyan/30 bg-cyan/5 py-2 text-[13px] font-medium text-cyan hover:bg-cyan/10 hover:border-cyan/50 transition-all shadow-[0_0_15px_rgba(94,207,255,0.05)]">
              <Plus size={16} />
              New Mission
            </button>
          </div>

          <nav className="flex flex-col gap-6 px-3">
            {/* Section: OPERATE */}
            <div className="flex flex-col gap-1">
              <span className="px-2 text-[10px] font-bold uppercase tracking-wider text-muted mb-1">Operate</span>
              <NavItem
                icon={<Crosshair size={15} />}
                label="Intake"
                active={activeTab === 'intake'}
                onClick={() => setActiveTab('intake')}
              />
              <NavItem
                icon={<Activity size={15} />}
                label="Mission Control"
                active={activeTab === 'mission-control'}
                onClick={() => setActiveTab('mission-control')}
                showLivingPulse={isRunning}
              />
            </div>

            {/* Section: ANALYZE */}
            <div className="flex flex-col gap-1">
              <span className="px-2 text-[10px] font-bold uppercase tracking-wider text-muted mb-1">Analyze</span>
              <NavItem
                icon={<ShieldAlert size={15} />}
                label="Findings"
                active={activeTab === 'findings'}
                onClick={() => setActiveTab('findings')}
                badge="3"
              />
              <NavItem
                icon={<FileText size={15} />}
                label="Reports"
                active={activeTab === 'reports'}
                onClick={() => setActiveTab('reports')}
              />
              <NavItem
                icon={<History size={15} />}
                label="History"
                active={activeTab === 'history'}
                onClick={() => setActiveTab('history')}
              />
            </div>

            {/* Section: BUILD */}
            <div className="flex flex-col gap-1">
              <span className="px-2 text-[10px] font-bold uppercase tracking-wider text-muted mb-1">Build</span>
              <NavItem
                icon={<Box size={15} />}
                label="Packs"
                active={activeTab === 'packs'}
                onClick={() => setActiveTab('packs')}
              />
            </div>
          </nav>

        </aside>

        {/* MAIN STAGE */}
        <main className="flex-1 relative overflow-hidden bg-[#04080f]">

          {/* Cinema-style background grid/web suggestion */}
          <div className="absolute inset-0 pointer-events-none opacity-20">
            <svg width="100%" height="100%" xmlns="http://www.w3.org/2000/svg">
              <defs>
                <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
                  <path d="M 40 0 L 0 0 0 40" fill="none" stroke="rgba(120,177,212,0.15)" strokeWidth="1"/>
                </pattern>
              </defs>
              <rect width="100%" height="100%" fill="url(#grid)" />
            </svg>
          </div>

          <div className="relative z-10 h-full p-8 overflow-y-auto">
            {activeTab === 'mission-control' && (
              <div className="max-w-5xl">
                <div className="flex items-center justify-between mb-8">
                  <div>
                    <h1 className="text-2xl font-semibold mb-2">Live Operations</h1>
                    <p className="text-muted text-[13px]">
                      Watching the spider move through the digital environment.
                    </p>
                  </div>
                  <button
                    onClick={() => setIsCinemaModeOpen(true)}
                    className="flex items-center gap-2 px-4 py-2 bg-[rgba(14,165,233,0.1)] border border-cyan/30 text-cyan rounded-lg text-sm font-semibold hover:bg-cyan/20 transition-all shadow-[0_0_15px_rgba(94,207,255,0.15)]"
                  >
                    <MonitorPlay size={16} />
                    Launch Cinema Mode
                  </button>
                </div>

                {/* Example Living Component */}
                <div className="glass-panel rounded-lg p-6 flex flex-col gap-4">
                  <div className="flex items-center justify-between">
                    <h2 className="text-sm font-medium text-cyan flex items-center gap-2">
                      <Activity size={14} className="animate-pulse" />
                      Active Run Thread
                    </h2>
                    <span className="text-[11px] text-muted">Started 2 mins ago</span>
                  </div>

                  <div className="h-[2px] w-full bg-border relative rounded-full overflow-hidden">
                    <div className="absolute top-0 left-0 h-full w-1/3 bg-cyan rounded-full animate-pulse-fast" />
                    <div className="absolute top-0 right-0 h-full w-1/4 bg-amber rounded-full opacity-50" />
                  </div>

                  <div className="flex justify-between text-[11px] text-muted">
                    <span>10.0.20.0/24 mapped</span>
                    <span>api.example.com queued</span>
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'intake' && (
              <div className="h-full w-full flex flex-col">
                <h1 className="text-2xl font-semibold mb-2">New Mission Intake</h1>
                <p className="text-muted text-[13px] mb-6">
                  Provide parameters or chat with Aegis Intelligence to configure the next run.
                </p>
                <div className="flex-1 min-h-0">
                  <Intake />
                </div>
              </div>
            )}

            {activeTab !== 'mission-control' && activeTab !== 'intake' && (
              <div>
                <h1 className="text-xl font-semibold capitalize">{activeTab.replace('-', ' ')}</h1>
              </div>
            )}
          </div>
        </main>
      </div>
    </div>
    </>
  );
}

// Sidebar Nav Item Component
function NavItem({
  icon,
  label,
  active,
  onClick,
  badge,
  showLivingPulse
}: {
  icon: React.ReactNode;
  label: string;
  active?: boolean;
  onClick: () => void;
  badge?: string;
  showLivingPulse?: boolean;
}) {
  return (
    <button
      onClick={onClick}
      className={cn(
        "group relative flex items-center justify-between w-full rounded-md px-2 py-1.5 text-[13px] font-medium transition-all duration-200",
        active
          ? "bg-cyan/10 text-cyan"
          : "text-muted hover:bg-surface hover:text-text"
      )}
    >
      <div className="flex items-center gap-2">
        <span className={cn(
          "transition-colors",
          active ? "text-cyan" : "text-muted group-hover:text-text"
        )}>
          {icon}
        </span>
        {label}
      </div>

      <div className="flex items-center gap-2">
        {badge && (
          <span className="flex h-4 min-w-[16px] items-center justify-center rounded-full bg-red/20 px-1 text-[10px] font-bold text-red">
            {badge}
          </span>
        )}
        {showLivingPulse && active && (
          <div className="h-1.5 w-1.5 rounded-full bg-cyan animate-pulse shadow-[0_0_5px_rgba(94,207,255,0.8)]" />
        )}
      </div>

      {/* Active Indicator Bar */}
      {active && (
        <div className="absolute left-0 top-[10%] h-[80%] w-[3px] rounded-r bg-cyan shadow-[0_0_8px_rgba(94,207,255,0.8)]" />
      )}
    </button>
  );
}