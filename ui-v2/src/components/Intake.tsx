import { useEffect, useMemo, useRef, useState } from 'react';
import type { ReactNode, RefObject } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import {
  ArrowLeft,
  ArrowRight,
  CheckCircle2,
  Cpu,
  Crosshair,
  Loader2,
  Play,
  Send,
  Shield,
  SlidersHorizontal,
  Sparkles,
  User,
} from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';
import {
  patchConfirmAuthorization,
  postEngagement,
  postInventoryRun,
  postRun,
  postRunIntakeInterpretation,
  postScope,
} from '../api/client';
import type { Engagement, JsonMap, RunIntakeInterpretation, UUID } from '../api/types';
import { useAegisStore } from '../store';
import { ASSESSMENT_TILES, type AssessmentTile, type PhaseTagTone } from './wizard/AssessmentTiles';

function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

type DepthKey = 'passive' | 'active' | 'full';
type WizardStep = 1 | 2 | 3;
type MissionField = 'targetType' | 'scope' | 'depth' | 'safety';

type Message = {
  id: string;
  sender: 'ai' | 'user';
  text: string;
  options?: string[];
  extractedData?: Partial<MissionSummary>;
};

type MissionSummary = {
  targetType: string | null;
  scope: string | null;
  depth: string | null;
  safety: string | null;
  assessmentTileKey?: string | null;
};

const openingMessage: Message = {
  id: 'opening',
  sender: 'ai',
  text: 'What are we testing? You can describe the full mission in one sentence — target, scope, and depth.',
  options: ['External Web App', 'Internal LAN', 'Active Directory', 'Cloud Infrastructure'],
};

const depthOptions: Array<{
  key: DepthKey;
  label: string;
  summary: string;
  phases: string[];
  safety: string;
}> = [
  {
    key: 'passive',
    label: 'Passive',
    summary: 'Seed inventory and passive-safe baseline checks.',
    phases: ['Phase 1 discovery'],
    safety: 'Low-impact, reviewed scope only',
  },
  {
    key: 'active',
    label: 'Active Scan',
    summary: 'Low-impact active recon through existing approval-aware runners.',
    phases: ['Phase 1 discovery', 'Phase 2 active validation'],
    safety: 'Approval-aware active checks',
  },
  {
    key: 'full',
    label: 'Full Pentest',
    summary: 'Full phase chain with later controlled proof gates still explicit.',
    phases: ['Discovery', 'Active validation', 'Credential context', 'Controlled proof gates'],
    safety: 'Written authorization plus later tier gates',
  },
];

export default function Intake() {
  const navigate = useNavigate();
  const engagements = useAegisStore((state) => state.engagements);
  const selectedEngagement = useAegisStore((state) => state.selectedEngagement);
  const runs = useAegisStore((state) => state.runs);
  const setEngagements = useAegisStore((state) => state.setEngagements);
  const selectEngagement = useAegisStore((state) => state.selectEngagement);
  const setRuns = useAegisStore((state) => state.setRuns);
  const setSelectedRun = useAegisStore((state) => state.setSelectedRun);
  const setInventory = useAegisStore((state) => state.setInventory);
  const setError = useAegisStore((state) => state.setError);

  const [mode, setMode] = useState<'manual' | 'ai'>('manual');
  const [isTyping, setIsTyping] = useState(false);
  const [inputValue, setInputValue] = useState('');
  const [isLaunching, setIsLaunching] = useState(false);
  const [showLaunchCeremony, setShowLaunchCeremony] = useState(false);
  const [launchError, setLaunchError] = useState<string | null>(null);
  const [authorizationConfirmed, setAuthorizationConfirmed] = useState(false);
  const [wizardStep, setWizardStep] = useState<WizardStep>(1);
  const [selectedTileKey, setSelectedTileKey] = useState<string | null>('external-web');
  const [wizardTarget, setWizardTarget] = useState('');
  const [wizardDepth, setWizardDepth] = useState<DepthKey>('passive');

  const [mission, setMission] = useState<MissionSummary>({
    targetType: null,
    scope: null,
    depth: null,
    safety: null,
    assessmentTileKey: null,
  });

  const [messages, setMessages] = useState<Message[]>([openingMessage]);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const selectedTile = useMemo(
    () => ASSESSMENT_TILES.find((tile) => tile.key === selectedTileKey) ?? ASSESSMENT_TILES[0],
    [selectedTileKey],
  );
  const selectedDepthOption = depthOptions.find((option) => option.key === wizardDepth) ?? depthOptions[0];
  const missionReady = Boolean(mission.targetType && mission.scope && mission.depth && mission.safety);
  const canLaunch = missionReady && authorizationConfirmed && !isLaunching;

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, isTyping]);

  function updateMission(update: Partial<MissionSummary>) {
    setMission((current) => ({ ...current, ...update }));
  }

  function applyWizardMission(tile: AssessmentTile, depth: DepthKey, target: string) {
    const depthOption = depthOptions.find((option) => option.key === depth) ?? depthOptions[0];
    updateMission({
      targetType: tile.assessmentType,
      scope: target.trim() || null,
      depth: depthOption.label,
      safety: depthOption.safety,
      assessmentTileKey: tile.key,
    });
  }

  async function ensureEngagement(): Promise<Engagement> {
    if (selectedEngagement) return selectedEngagement;
    const created = await postEngagement({
      name: `React v2 Intake Mission ${new Date().toISOString().slice(0, 16).replace('T', ' ')}`,
      client: null,
      roe_ref: null,
    });
    setEngagements([created, ...engagements.filter((engagement) => engagement.id !== created.id)]);
    selectEngagement(created.id);
    return created;
  }

  async function handleSend(text: string) {
    const answer = text.trim();
    if (!answer || isTyping) return;

    const field = nextEmptyField(mission);
    const userMsg: Message = { id: crypto.randomUUID(), sender: 'user', text: answer };
    setMessages((current) => [...current, userMsg]);
    setInputValue('');
    setLaunchError(null);

    // All fields already complete — no more API calls needed
    if (field === 'complete') {
      setMessages((current) => [
        ...current,
        {
          id: crypto.randomUUID(),
          sender: 'ai',
          text: 'Mission profile is complete. Confirm authorization in the sidebar and hit launch.',
        },
      ]);
      return;
    }

    setIsTyping(true);
    try {
      const engagement = await ensureEngagement();
      const interpretation = await postRunIntakeInterpretation({
        question_id: field,
        answer,
        engagement_id: engagement.id,
        configuration_json: buildConfigurationPreview({
          ...mission,
          [field]: answer,
        }),
      });
      const extracted = extractMissionUpdate(field, answer, interpretation, mission);
      updateMission(extracted);
      const nextField = nextEmptyField({ ...mission, ...extracted });
      setMessages((current) => [
        ...current,
        {
          id: crypto.randomUUID(),
          sender: 'ai',
          text: responseTextForInterpretation(interpretation, nextField, extracted),
          options: optionsForNextField(nextField),
          extractedData: extracted,
        },
      ]);
    } catch (error) {
      const message = errorMessage(error);
      setError(message);
      setLaunchError(message);
      setMessages((current) => [
        ...current,
        {
          id: crypto.randomUUID(),
          sender: 'ai',
          text: `Could not process that — try again or switch to Manual Wizard.`,
        },
      ]);
    } finally {
      setIsTyping(false);
    }
  }

  async function launchMission() {
    if (!missionReady || !authorizationConfirmed || isLaunching) return;
    setIsLaunching(true);
    setLaunchError(null);
    setError(null);
    setShowLaunchCeremony(true);
    await new Promise((resolve) => setTimeout(resolve, 1200));
    try {
      let engagement = await ensureEngagement();
      if (!engagement.roe_ref && !engagement.authorization_confirmed_at) {
        const authorization = await patchConfirmAuthorization(engagement.id);
        engagement = {
          ...engagement,
          authorization_confirmed_by: stringValue(authorization.authorization_confirmed_by),
          authorization_confirmed_at: stringValue(authorization.authorization_confirmed_at),
        };
        setEngagements([engagement, ...engagements.filter((candidate) => candidate.id !== engagement.id)]);
        selectEngagement(engagement.id);
      }

      const targetMap = targetMapFromScope(mission.scope || '', mission.targetType || '');
      await postScope(engagement.id, {
        allowlist_json: targetMap,
        denylist_json: {},
      });

      const inventorySnapshot = await postInventoryRun({
        engagement_id: engagement.id,
        source_tools: ['wizard-input'],
        observations: [
          {
            tool: 'wizard-input',
            kind: 'inventory-seed',
            data: inventorySeedData(targetMap, mission.targetType || ''),
          },
        ],
        environment_notes: [
          `React v2 intake source: split-path`,
          `Assessment type: ${mission.targetType}`,
          `Depth: ${mission.depth}`,
          `Safety posture: ${mission.safety}`,
        ],
        assumptions: ['Seed inventory was created from operator-reviewed React v2 intake input before active discovery.'],
      });

      const runRequest = buildRunRequest(mission, inventorySnapshot.id);
      const run = await postRun(engagement.id, runRequest);
      setInventory(inventorySnapshot);
      setRuns([run, ...runs.filter((candidate) => candidate.id !== run.id)]);
      setSelectedRun(run);
      setShowLaunchCeremony(false);
      navigate('/mission-control');
    } catch (error) {
      const message = errorMessage(error);
      setError(message);
      setLaunchError(message);
      setShowLaunchCeremony(false);
    } finally {
      setIsLaunching(false);
      setShowLaunchCeremony(false);
    }
  }

  function handleTileSelect(tile: AssessmentTile) {
    setSelectedTileKey(tile.key);
    updateMission({
      targetType: tile.assessmentType,
      assessmentTileKey: tile.key,
    });
  }

  function handleWizardTargetChange(target: string) {
    setWizardTarget(target);
    applyWizardMission(selectedTile, wizardDepth, target);
  }

  function handleWizardDepthChange(depth: DepthKey) {
    setWizardDepth(depth);
    applyWizardMission(selectedTile, depth, wizardTarget);
  }

  return (
    <>
      <AnimatePresence>
        {showLaunchCeremony && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-50 flex items-center justify-center bg-[#04080f]/90 backdrop-blur-md"
          >
             <div className="flex flex-col items-center gap-6">
                <Crosshair className="text-cyan animate-[spin_4s_linear_infinite]" size={64} />
                <h1 className="text-3xl font-bold uppercase tracking-widest text-cyan">Mission locked. Deploying.</h1>
             </div>
          </motion.div>
        )}
      </AnimatePresence>

      <div className="flex h-full w-full min-h-0 gap-5">
        {/* Main pane — tabbed: Manual Wizard or AI Guided */}
        <div className="flex min-h-0 flex-1 flex-col overflow-hidden rounded-xl border border-border bg-[rgba(8,14,26,0.7)] shadow-2xl backdrop-blur-md">
          {/* Mode switcher */}
          <div className="shrink-0 flex items-center justify-between gap-4 border-b border-border bg-[rgba(4,8,15,0.85)] px-5 py-3">
            <div className="flex items-center gap-1 rounded-lg border border-border bg-bg/60 p-1">
              <button
                type="button"
                onClick={() => setMode('manual')}
                className={cn(
                  'flex items-center gap-2 rounded-md px-4 py-1.5 text-[0.85rem] font-semibold transition-all',
                  mode === 'manual' ? 'bg-cyan/10 text-cyan shadow-[0_0_12px_rgba(94,207,255,0.12)]' : 'text-muted hover:text-text',
                )}
              >
                <SlidersHorizontal size={13} />
                Manual Wizard
              </button>
              <button
                type="button"
                onClick={() => setMode('ai')}
                className={cn(
                  'flex items-center gap-2 rounded-md px-4 py-1.5 text-[0.85rem] font-semibold transition-all',
                  mode === 'ai' ? 'bg-cyan/10 text-cyan shadow-[0_0_12px_rgba(94,207,255,0.12)]' : 'text-muted hover:text-text',
                )}
              >
                <Sparkles size={13} />
                Guided Intake
              </button>
            </div>
            {mode === 'ai' && (
              <span className="flex items-center gap-2 text-[0.77rem] font-mono uppercase tracking-widest text-cyan/60">
                <span className="h-1.5 w-1.5 rounded-full bg-cyan animate-pulse" />
                Backend connected
              </span>
            )}
          </div>

          <AnimatePresence mode="wait">
            {mode === 'manual' ? (
              <motion.div key="manual" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={{ duration: 0.12 }} className="flex min-h-0 flex-1 flex-col">
                <WizardPane
                  step={wizardStep}
                  setStep={setWizardStep}
                  selectedTile={selectedTile}
                  selectedTileKey={selectedTileKey}
                  onTileSelect={handleTileSelect}
                  target={wizardTarget}
                  onTargetChange={handleWizardTargetChange}
                  targetKind={targetKind(wizardTarget)}
                  depth={wizardDepth}
                  onDepthChange={handleWizardDepthChange}
                  depthOption={selectedDepthOption}
                  canPreview={Boolean(selectedTileKey && wizardTarget.trim() && wizardDepth)}
                  authorizationConfirmed={authorizationConfirmed}
                  setAuthorizationConfirmed={setAuthorizationConfirmed}
                  isLaunching={isLaunching}
                  onLaunch={() => void launchMission()}
                />
              </motion.div>
            ) : (
              <motion.div key="ai" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={{ duration: 0.12 }} className="flex min-h-0 flex-1 flex-col">
                <AiIntakePane
                  messages={messages}
                  isTyping={isTyping}
                  inputValue={inputValue}
                  setInputValue={setInputValue}
                  handleSend={handleSend}
                  messagesEndRef={messagesEndRef}
                />
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        {/* Mission Profile sidebar */}
        <MissionProfile
          mission={mission}
          latestExtraction={messages[messages.length - 1]?.extractedData}
          authorizationConfirmed={authorizationConfirmed}
          setAuthorizationConfirmed={setAuthorizationConfirmed}
          canLaunch={canLaunch}
          isLaunching={isLaunching}
          launchError={launchError}
          onLaunch={() => void launchMission()}
        />
      </div>
    </>
  );
}

function AiIntakePane({
  messages,
  isTyping,
  inputValue,
  setInputValue,
  handleSend,
  messagesEndRef,
}: {
  messages: Message[];
  isTyping: boolean;
  inputValue: string;
  setInputValue: (value: string) => void;
  handleSend: (text: string) => void;
  messagesEndRef: RefObject<HTMLDivElement>;
}) {
  return (
    <>
      <div className="min-h-0 flex-1 space-y-6 overflow-y-auto p-5">
        <AnimatePresence initial={false}>
          {messages.map((msg) => (
            <motion.div
              key={msg.id}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className={cn('flex max-w-[88%] flex-col', msg.sender === 'user' ? 'ml-auto items-end' : 'mr-auto items-start')}
            >
              <div className={cn('flex items-end gap-3', msg.sender === 'user' ? 'flex-row-reverse' : 'flex-row')}>
                <div
                  className={cn(
                    'flex h-8 w-8 shrink-0 items-center justify-center rounded-full border shadow-lg',
                    msg.sender === 'ai' ? 'border-cyan/30 bg-cyan/10 text-cyan' : 'border-border bg-surface text-text',
                  )}
                >
                  {msg.sender === 'ai' ? <Cpu size={16} /> : <User size={16} />}
                </div>
                <div
                  className={cn(
                    'rounded-2xl px-5 py-3 text-[1.08rem] leading-relaxed shadow-sm',
                    msg.sender === 'user'
                      ? 'rounded-br-sm border border-border bg-surface text-text'
                      : 'rounded-bl-sm border border-[rgba(14,165,233,0.15)] bg-[rgba(14,165,233,0.05)] text-cyan',
                  )}
                >
                  {msg.text}
                </div>
              </div>
              {msg.options && (
                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  className={cn('mt-3 flex flex-wrap gap-2', msg.sender === 'user' ? 'justify-end' : 'justify-start pl-11')}
                >
                  {msg.options.map((opt) => (
                    <button
                      key={opt}
                      onClick={() => handleSend(opt)}
                      className="rounded-full border border-border bg-surface px-4 py-1.5 text-xs font-semibold text-muted shadow-[0_2px_10px_rgba(0,0,0,0.2)] transition-all hover:border-cyan/50 hover:bg-cyan/5 hover:text-cyan"
                    >
                      {opt}
                    </button>
                  ))}
                </motion.div>
              )}
            </motion.div>
          ))}
          {isTyping && (
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="mr-auto flex items-end gap-3">
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full border border-cyan/30 bg-cyan/10 text-cyan">
                <Cpu size={16} />
              </div>
              <div className="flex items-center gap-1.5 rounded-2xl rounded-bl-sm border border-[rgba(14,165,233,0.15)] bg-[rgba(14,165,233,0.05)] px-5 py-4">
                <span className="h-1.5 w-1.5 rounded-full bg-cyan animate-bounce" />
                <span className="h-1.5 w-1.5 rounded-full bg-cyan animate-bounce [animation-delay:150ms]" />
                <span className="h-1.5 w-1.5 rounded-full bg-cyan animate-bounce [animation-delay:300ms]" />
              </div>
            </motion.div>
          )}
        </AnimatePresence>
        <div ref={messagesEndRef} />
      </div>
      <div className="border-t border-border bg-[rgba(5,9,18,0.8)] p-4">
        <div className="relative flex items-center">
          <input
            type="text"
            value={inputValue}
            onChange={(event) => setInputValue(event.target.value)}
            onKeyDown={(event) => event.key === 'Enter' && handleSend(inputValue)}
            placeholder="Type an assessment type, target, depth, or safety posture"
            className="w-full rounded-xl border border-border bg-surface py-3 pl-4 pr-12 text-sm text-text shadow-inner transition-all placeholder:text-muted focus:border-cyan/50 focus:outline-none focus:ring-1 focus:ring-cyan/50"
            disabled={isTyping}
          />
          <button
            onClick={() => handleSend(inputValue)}
            disabled={!inputValue.trim() || isTyping}
            className="absolute right-2 rounded-lg p-2 text-cyan transition-colors hover:bg-cyan/10 disabled:opacity-50 disabled:hover:bg-transparent"
            aria-label="Send intake answer"
          >
            <Send size={18} />
          </button>
        </div>
      </div>
    </>
  );
}

function WizardPane({
  step,
  setStep,
  selectedTile,
  selectedTileKey,
  onTileSelect,
  target,
  onTargetChange,
  targetKind,
  depth,
  onDepthChange,
  depthOption,
  canPreview,
  authorizationConfirmed,
  setAuthorizationConfirmed,
  isLaunching,
  onLaunch,
}: {
  step: WizardStep;
  setStep: (step: WizardStep) => void;
  selectedTile: AssessmentTile;
  selectedTileKey: string | null;
  onTileSelect: (tile: AssessmentTile) => void;
  target: string;
  onTargetChange: (target: string) => void;
  targetKind: string;
  depth: DepthKey;
  onDepthChange: (depth: DepthKey) => void;
  depthOption: (typeof depthOptions)[number];
  canPreview: boolean;
  authorizationConfirmed: boolean;
  setAuthorizationConfirmed: (value: boolean) => void;
  isLaunching: boolean;
  onLaunch: () => void;
}) {
  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="border-b border-border px-5 py-4">
        <div className="flex flex-wrap items-center gap-2">
          {[1, 2, 3].map((item) => (
            <button
              key={item}
              type="button"
              onClick={() => setStep(item as WizardStep)}
              className={cn(
                'rounded-full border px-3 py-1 text-[0.85rem] font-bold uppercase tracking-wide',
                step === item ? 'border-cyan/40 bg-cyan/10 text-cyan' : 'border-border text-muted',
              )}
            >
              {item === 1 ? 'Assessment' : item === 2 ? 'Target & Depth' : 'Preview'}
            </button>
          ))}
        </div>
      </div>

      {step === 1 && (
        <div className="min-h-0 flex-1 overflow-y-auto p-5">
          <div className="mb-4">
            <h2 className="text-lg font-semibold text-text">Select Assessment Type</h2>
            <p className="mt-1 text-[1rem] text-muted">Choose the surface that best matches the authorized target.</p>
          </div>
          <div className="grid gap-4 grid-cols-2 xl:grid-cols-3">
            {ASSESSMENT_TILES.map((tile) => {
              const Icon = tile.icon;
              const selected = selectedTileKey === tile.key;
              return (
                <button
                  key={tile.key}
                  type="button"
                  onClick={() => onTileSelect(tile)}
                  data-testid={`wizard-assessment-tile-${tile.key}`}
                  aria-pressed={selected}
                  className={cn(
                    'min-h-[156px] rounded-lg border p-4 text-left transition-all',
                    selected ? 'border-cyan/50 bg-cyan/10 shadow-[0_0_18px_rgba(94,207,255,0.12)]' : 'border-border bg-surface/45 hover:border-cyan/30',
                  )}
                >
                  <div className="mb-3 flex items-center justify-between gap-3">
                    <span className="flex h-9 w-9 items-center justify-center rounded-md border border-cyan/20 bg-cyan/10 text-cyan">
                      <Icon size={17} />
                    </span>
                    {tile.badge && (
                      <span className="rounded-full border border-border bg-bg/70 px-2 py-0.5 text-[0.77rem] font-bold uppercase text-muted">
                        {tile.badge}
                      </span>
                    )}
                  </div>
                  <div className="text-[1rem] font-semibold text-text">{tile.label}</div>
                  <p className="mt-2 line-clamp-3 text-[0.925rem] leading-5 text-muted">{tile.description}</p>
                  <div className="mt-3 flex flex-wrap gap-1.5">
                    {tile.phaseTags.map((tag) => (
                      <PhaseTag key={`${tile.key}-${tag.label}`} label={tag.label} tone={tag.tone} />
                    ))}
                  </div>
                </button>
              );
            })}
          </div>
          <div className="mt-5 flex justify-end">
            <button
              type="button"
              disabled={!selectedTileKey}
              onClick={() => setStep(2)}
              className="inline-flex items-center gap-2 rounded-md border border-cyan/30 bg-cyan/10 px-4 py-2 text-[1rem] font-semibold text-cyan transition-colors hover:bg-cyan/15 disabled:cursor-not-allowed disabled:opacity-40"
            >
              Target & Depth
              <ArrowRight size={15} />
            </button>
          </div>
        </div>
      )}

      {step === 2 && (
        <div className="min-h-0 flex-1 overflow-y-auto p-5">
          <div className="mb-5 flex flex-col gap-2">
            <h2 className="text-lg font-semibold text-text">Target & Depth</h2>
            <p className="text-[1rem] text-muted">The target is stored as allowlisted scope before a run can exist.</p>
          </div>
          <label className="block text-[0.925rem] font-bold uppercase tracking-wide text-muted" htmlFor="wizard-target">
            Approved target
          </label>
          <input
            id="wizard-target"
            value={target}
            onChange={(event) => onTargetChange(event.target.value)}
            placeholder="https://app.example.test, 10.0.20.0/24, api.example.test"
            className="mt-2 w-full rounded-lg border border-border bg-surface px-4 py-3 text-sm text-text outline-none transition-colors placeholder:text-muted focus:border-cyan/50"
          />
          <p className="mt-2 text-[0.925rem] text-muted">Detected target type: {targetKind}</p>

          <div className="mt-6 grid gap-3 md:grid-cols-3">
            {depthOptions.map((option) => {
              const selected = depth === option.key;
              return (
                <button
                  key={option.key}
                  type="button"
                  onClick={() => onDepthChange(option.key)}
                  className={cn(
                    'min-h-[150px] rounded-lg border p-4 text-left transition-colors',
                    selected ? 'border-cyan/50 bg-cyan/10' : 'border-border bg-surface/45 hover:border-cyan/30',
                  )}
                >
                  <div className="text-[1rem] font-semibold text-text">{option.label}</div>
                  <p className="mt-2 text-[0.925rem] leading-5 text-muted">{option.summary}</p>
                  <div className="mt-3 flex flex-wrap gap-1.5">
                    {option.phases.map((phase) => (
                      <span key={phase} className="rounded-full border border-border px-2 py-0.5 text-[0.77rem] text-muted">
                        {phase}
                      </span>
                    ))}
                  </div>
                </button>
              );
            })}
          </div>

          <div className="mt-5 flex justify-between gap-3">
            <button
              type="button"
              onClick={() => setStep(1)}
              className="inline-flex items-center gap-2 rounded-md border border-border bg-surface/60 px-4 py-2 text-[1rem] font-semibold text-muted hover:text-text"
            >
              <ArrowLeft size={15} />
              Back
            </button>
            <button
              type="button"
              disabled={!canPreview}
              onClick={() => setStep(3)}
              className="inline-flex items-center gap-2 rounded-md border border-cyan/30 bg-cyan/10 px-4 py-2 text-[1rem] font-semibold text-cyan transition-colors hover:bg-cyan/15 disabled:cursor-not-allowed disabled:opacity-40"
            >
              Preview Mission
              <ArrowRight size={15} />
            </button>
          </div>
        </div>
      )}

      {step === 3 && (
        <div className="min-h-0 flex-1 overflow-y-auto p-5">
          <div className="rounded-lg border border-border bg-surface/45 p-5">
            <div className="mb-4 flex flex-wrap items-center gap-2">
              <span className="rounded-full border border-cyan/30 bg-cyan/10 px-3 py-1 text-[0.85rem] font-bold uppercase text-cyan">
                {selectedTile.assessmentType}
              </span>
              <span className="rounded-full border border-border px-3 py-1 text-[0.85rem] font-bold uppercase text-muted">
                {depthOption.label}
              </span>
            </div>
            <h2 className="text-lg font-semibold text-text">Mission Preview</h2>
            <dl className="mt-4 grid gap-3 text-[1rem]">
              <PreviewRow label="Target" value={target || 'Not set'} />
              <PreviewRow label="Safety" value={depthOption.safety} />
              <PreviewRow label="Phases" value={depthOption.phases.join(' · ')} />
              <PreviewRow label="Estimated time" value={depthOption.key === 'passive' ? 'About 5 minutes' : depthOption.key === 'active' ? 'About 15 minutes' : 'Runs fully automated through all phases'} />
              {depthOption.key === 'full' && (
                <div className="rounded-md border border-cyan/20 bg-cyan/5 px-3 py-2 text-[0.85rem] text-cyan/80">
                  Full Pentest runs without phase approval gates — all phases execute automatically once launched.
                </div>
              )}
            </dl>
            <label className="mt-5 flex items-start gap-3 rounded-md border border-amber/30 bg-amber/10 p-3 text-[1rem] text-text">
              <input
                type="checkbox"
                checked={authorizationConfirmed}
                onChange={(event) => setAuthorizationConfirmed(event.target.checked)}
                className="mt-1"
              />
              <span>
                <strong>I confirm written authorization from the system owner.</strong>
                <span className="mt-1 block text-[0.925rem] text-muted">
                  This creates an auditable authorization confirmation before the run can start.
                </span>
              </span>
            </label>
          </div>
          <div className="mt-5 flex justify-between gap-3">
            <button
              type="button"
              onClick={() => setStep(2)}
              className="inline-flex items-center gap-2 rounded-md border border-border bg-surface/60 px-4 py-2 text-[1rem] font-semibold text-muted hover:text-text"
            >
              <ArrowLeft size={15} />
              Back
            </button>
            <button
              type="button"
              disabled={!authorizationConfirmed || isLaunching}
              onClick={onLaunch}
              className="inline-flex items-center gap-2 rounded-md bg-cyan px-4 py-2 text-[1rem] font-bold text-[#04080f] shadow-[0_0_20px_rgba(94,207,255,0.35)] transition-all hover:shadow-[0_0_28px_rgba(94,207,255,0.5)] disabled:cursor-not-allowed disabled:opacity-40"
            >
              {isLaunching ? <Loader2 size={15} className="animate-spin" /> : <Play size={15} />}
              Create Mission & Open Mission Control
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

function MissionProfile({
  mission,
  latestExtraction,
  authorizationConfirmed,
  setAuthorizationConfirmed,
  canLaunch,
  isLaunching,
  launchError,
  onLaunch,
}: {
  mission: MissionSummary;
  latestExtraction?: Partial<MissionSummary>;
  authorizationConfirmed: boolean;
  setAuthorizationConfirmed: (value: boolean) => void;
  canLaunch: boolean;
  isLaunching: boolean;
  launchError: string | null;
  onLaunch: () => void;
}) {
  return (
    <aside className="min-h-0">
      <div className="relative flex h-full flex-col overflow-hidden rounded-xl border border-border bg-surface/50 backdrop-blur-md">
        <div className="pointer-events-none absolute -right-[100px] -top-[100px] opacity-10">
          <Crosshair size={300} className="text-cyan animate-[spin_60s_linear_infinite]" />
        </div>
        <div className="relative z-10 border-b border-border bg-[rgba(5,9,18,0.8)] p-5">
          <h2 className="text-sm font-bold uppercase tracking-widest text-text">Mission Profile</h2>
          <p className="mt-1 text-[0.85rem] text-muted">Operator-reviewed launch data</p>
        </div>
        <div className="relative z-10 flex-1 space-y-4 overflow-y-auto p-5">
          <SummaryCard
            label="Target Type"
            value={mission.targetType}
            icon={<Crosshair size={14} />}
            isLatest={latestExtraction?.targetType !== undefined}
          />
          <SummaryCard
            label="Scope & Targets"
            value={mission.scope}
            icon={<Crosshair size={14} />}
            isLatest={latestExtraction?.scope !== undefined}
          />
          <SummaryCard
            label="Execution Depth"
            value={mission.depth}
            icon={<Shield size={14} />}
            isLatest={latestExtraction?.depth !== undefined}
          />
          <SummaryCard
            label="Safety Posture"
            value={mission.safety}
            icon={<CheckCircle2 size={14} />}
            isLatest={latestExtraction?.safety !== undefined}
          />
          <label className="flex items-start gap-3 rounded-lg border border-border bg-[rgba(5,9,18,0.4)] p-4 text-[0.925rem] text-text">
            <input
              type="checkbox"
              checked={authorizationConfirmed}
              onChange={(event) => setAuthorizationConfirmed(event.target.checked)}
              className="mt-1"
            />
            <span>
              <strong>Written authorization confirmed</strong>
              <span className="mt-1 block leading-5 text-muted">Required before scope, inventory, and run creation.</span>
            </span>
          </label>
          {launchError && <div className="rounded-md border border-red/30 bg-red/10 p-3 text-[0.925rem] text-red">{launchError}</div>}
          <button
            type="button"
            disabled={!canLaunch}
            onClick={onLaunch}
            className="flex w-full items-center justify-center gap-2 rounded-lg bg-cyan py-3 text-sm font-bold text-[#04080f] shadow-[0_0_20px_rgba(94,207,255,0.35)] transition-all hover:shadow-[0_0_30px_rgba(94,207,255,0.55)] disabled:cursor-not-allowed disabled:opacity-40"
          >
            {isLaunching ? <Loader2 size={16} className="animate-spin" /> : <Sparkles size={16} />}
            Confirm & Launch Mission
          </button>
        </div>
      </div>
    </aside>
  );
}

function SummaryCard({ label, value, icon, isLatest }: { label: string; value: string | null; icon: ReactNode; isLatest: boolean }) {
  return (
    <motion.div
      initial={false}
      animate={{
        borderColor: isLatest ? 'rgba(94,207,255,0.8)' : 'rgba(120,177,212,0.15)',
        boxShadow: isLatest ? '0 0 15px rgba(94,207,255,0.15) inset' : 'none',
      }}
      transition={{ duration: 0.5 }}
      className="relative overflow-hidden rounded-lg border border-border bg-[rgba(5,9,18,0.4)] p-4"
    >
      {isLatest && (
        <motion.div
          initial={{ left: '-100%' }}
          animate={{ left: '200%' }}
          transition={{ duration: 1.5, ease: 'easeInOut' }}
          className="absolute bottom-0 top-0 w-[50px] skew-x-[-20deg] bg-gradient-to-r from-transparent via-cyan/20 to-transparent"
        />
      )}
      <div className="mb-2 flex items-center gap-2 text-[0.77rem] font-bold uppercase tracking-widest text-muted">
        {icon}
        {label}
      </div>
      {value ? (
        <motion.div initial={{ opacity: 0, y: 5 }} animate={{ opacity: 1, y: 0 }} className="break-words text-[1rem] font-semibold text-text">
          {value}
        </motion.div>
      ) : (
        <div className="text-[1rem] italic text-muted/40">Awaiting input...</div>
      )}
    </motion.div>
  );
}

function PreviewRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="grid gap-1 rounded-md border border-border bg-bg/30 p-3 sm:grid-cols-[120px_1fr]">
      <dt className="text-muted">{label}</dt>
      <dd className="break-words text-text">{value}</dd>
    </div>
  );
}

function PhaseTag({ label, tone }: { label: string; tone: PhaseTagTone }) {
  return (
    <span
      className={cn(
        'rounded-full border px-2 py-0.5 text-[0.77rem] font-semibold',
        tone === 'passive' && 'border-emerald-400/30 bg-emerald-400/10 text-emerald-200',
        tone === 'active' && 'border-cyan/30 bg-cyan/10 text-cyan',
        tone === 'credential' && 'border-violet-300/30 bg-violet-300/10 text-violet-100',
        tone === 'proof' && 'border-amber/30 bg-amber/10 text-amber',
        tone === 'custom' && 'border-border bg-bg/40 text-muted',
      )}
    >
      {label}
    </span>
  );
}

function nextEmptyField(mission: MissionSummary): MissionField | 'complete' {
  if (!mission.targetType) return 'targetType';
  if (!mission.scope) return 'scope';
  if (!mission.depth) return 'depth';
  // Full Pentest authorization covers safety — no separate question needed
  const isFullPentest = (mission.depth || '').toLowerCase().includes('full');
  if (!mission.safety && !isFullPentest) return 'safety';
  return 'complete';
}

function extractMissionUpdate(
  field: MissionField,
  answer: string,
  interpretation: RunIntakeInterpretation,
  currentMission: MissionSummary,
): Partial<MissionSummary> {
  const update: Partial<MissionSummary> = {};

  // Extract from LLM inferences when available
  for (const inference of interpretation.safe_inferences ?? []) {
    const inferredField = stringValue(inference.field);
    const inferredValue = stringValue(inference.value);
    if (inferredField === 'assessment_type' && inferredValue) update.targetType = inferredValue;
    if (inferredField === 'safety_posture' && inferredValue) update.safety = humanizeSafety(inferredValue);
    if (inferredField === 'primary_goal' && inferredValue) update.depth = humanizeGoal(inferredValue);
    if ((inferredField === 'scope' || inferredField === 'target_url') && inferredValue) update.scope = inferredValue;
  }

  // Free-text extraction — only for fields not yet filled in the current mission
  const lower = answer.toLowerCase();
  if (!currentMission.scope && !update.scope) {
    const urlMatch = answer.match(/https?:\/\/\S+/);
    if (urlMatch) update.scope = urlMatch[0].replace(/[,.]$/, '');
  }
  if (!currentMission.depth) {
    if (describesFullPentest(lower)) {
      update.depth = 'Full Pentest';
      // Full Pentest authorization is confirmed by the written authorization checkbox — no safety question needed
      if (!currentMission.safety) update.safety = 'Full pentest — written authorization confirmed';
    } else if (describesActiveScan(lower)) {
      update.depth = 'Active Scan';
    } else if (describesPassiveScan(lower)) {
      update.depth = 'Passive';
    }
  }

  // Field-specific extraction
  if (field === 'targetType') {
    const tile = tileFromAnswer(answer);
    update.targetType = update.targetType || tile.assessmentType;
    update.assessmentTileKey = tile.key;
  }
  if (field === 'scope' && !update.scope && !currentMission.scope) update.scope = answer;
  if (field === 'depth' && !update.depth) update.depth = humanizeDepth(answer);
  if (field === 'safety' && !update.safety) update.safety = answer;

  return update;
}

function optionsForNextField(field: MissionField | 'complete'): string[] | undefined {
  if (field === 'targetType') return ['External Web App', 'Internal LAN', 'API Security', 'Authenticated App'];
  if (field === 'depth') return ['Passive', 'Active Scan', 'Full Pentest'];
  if (field === 'safety') return ['Conservative and low-impact', 'Active checks with approvals'];
  return undefined;
}

function responseTextForInterpretation(
  interpretation: RunIntakeInterpretation,
  field: MissionField | 'complete',
  extracted: Partial<MissionSummary>,
): string {
  if (field === 'complete') return nextPrompt(field, extracted);
  if (interpretation.available && interpretation.follow_up_questions?.length) {
    const question = stringValue(interpretation.follow_up_questions[0].question);
    if (question) return question;
  }
  return nextPrompt(field, extracted);
}

function nextPrompt(field: MissionField | 'complete', extracted: Partial<MissionSummary>): string {
  if (field === 'targetType') return `What environment are we testing? (e.g. web app, internal LAN, API, AD)`;
  if (field === 'scope') {
    const prefix = extracted.targetType ? `${extracted.targetType} — ` : '';
    return `${prefix}what's the target? Provide a URL, IP range, or domain.`;
  }
  if (field === 'depth') {
    const prefix = extracted.scope ? `Got it — ${extracted.scope}. ` : '';
    return `${prefix}Execution depth: Passive (reconnaissance only), Active Scan, or Full Pentest (all phases, no approval gates)?`;
  }
  if (field === 'safety') {
    const prefix = extracted.depth ? `${extracted.depth} selected. ` : '';
    return `${prefix}Safety posture: conservative (low-impact) or active scanning?`;
  }
  const isFullPentest = (extracted.depth || '').toLowerCase().includes('full');
  return isFullPentest
    ? `Full Pentest ready — all phases authorized, no approval gates. Confirm written authorization in the sidebar and launch.`
    : `All fields set. Confirm written authorization in the sidebar and launch.`;
}

function tileFromAnswer(answer: string): AssessmentTile {
  const normalized = answer.toLowerCase();
  return (
    ASSESSMENT_TILES.find((tile) => {
      const haystack = `${tile.key} ${tile.label} ${tile.assessmentType} ${tile.quickReply}`.toLowerCase();
      return haystack.includes(normalized) || normalized.includes(tile.label.toLowerCase()) || normalized.includes(tile.key.replace(/-/g, ' '));
    }) ?? ASSESSMENT_TILES[0]
  );
}

function buildConfigurationPreview(mission: MissionSummary): JsonMap {
  return {
    assessment_type: mission.targetType,
    test_profile: mission.depth,
    targets: targetMapFromScope(mission.scope || '', mission.targetType || ''),
    safety: { posture: mission.safety },
    intake: { mode: 'react-v2-ai' },
  };
}

function buildRunRequest(mission: MissionSummary, inventoryId: UUID) {
  const profile = profileForMission(mission);
  const assessmentMode = assessmentModeForMission(mission);
  const isFullPentest = (mission.depth || '').toLowerCase().includes('full');
  const firstTarget = firstTargetValue(targetMapFromScope(mission.scope || '', mission.targetType || ''));
  // Full Pentest gets full authorization so the chain auto-advances without approval gates.
  // The operator already confirmed written authorization via the checkbox.
  const authLevel = isFullPentest ? 'full' : 'active';
  const configuration: JsonMap = {
    assessment_type: mission.targetType,
    test_profile: mission.depth,
    execution_profile: profile,
    targets: targetMapFromScope(mission.scope || '', mission.targetType || ''),
    safety: {
      posture: mission.safety,
      controlled_proof_requires_later_approval: !isFullPentest,
    },
    intake: {
      mode: 'react-v2',
      confirmation_summary: `${mission.targetType} against ${mission.scope} at ${mission.depth} depth.`,
    },
    assessment_mode: assessmentMode
      ? {
          enabled: true,
          mode: assessmentMode,
          authorization_level: authLevel,
          confirmed_scope: mission.scope,
          confirmation_target: firstTarget,
          // Must match confirmation_target for full authorization to pass backend validation
          typed_scope_confirmation: isFullPentest ? firstTarget : '',
          intrusive_lan_authorized: isFullPentest,
          exploit_confirmation_authorized: isFullPentest,
        }
      : { enabled: false },
  };
  return {
    profile_name: profile,
    source_inventory_snapshot_id: inventoryId,
    configuration_json: configuration,
    assessment_mode: assessmentMode,
    assessment_auto_advance_on_phase_complete: Boolean(assessmentMode),
    dispatch_after_create: true,
  };
}

function profileForMission(mission: MissionSummary): string {
  const type = (mission.targetType || '').toLowerCase();
  const depth = (mission.depth || '').toLowerCase();
  const isFull = depth.includes('full');
  const isActive = depth.includes('active');

  if (type.includes('wifi')) return 'passive-wifi-survey';
  if (type.includes('cloud')) return 'passive-cloud-aws-inventory';
  if (type.includes('ssl')) return 'passive-crypto-audit';

  if (type.includes('directory') || type.includes('active directory')) {
    return isFull ? 'passive-network-discovery' : isActive ? 'passive-network-service-enumeration' : 'passive-network-discovery';
  }
  if (type.includes('internal') || type.includes('lan')) {
    return isFull || isActive ? 'passive-network-service-enumeration' : 'passive-network-discovery';
  }
  if (type.includes('api')) {
    return isFull || isActive ? 'active-api-assessment' : 'passive-web-baseline';
  }

  // Web / default
  // Full pentest: chain handles all phases; first phase starts with passive baseline discovery
  if (isFull) return 'passive-web-baseline';
  if (isActive) return 'active-low-impact-web-recon';
  return 'passive-web-baseline';
}

function assessmentModeForMission(mission: MissionSummary): string | null {
  const type = (mission.targetType || '').toLowerCase();
  const depth = (mission.depth || '').toLowerCase();
  if (!depth.includes('full')) return null;
  if (type.includes('directory')) return 'FULL-AD-ASSESSMENT';
  if (type.includes('internal')) return 'FULL-INTERNAL-LAN';
  if (type.includes('web') || type.includes('api') || type.includes('authenticated')) return 'FULL-EXTERNAL-WEB';
  return null;
}

function targetMapFromScope(scope: string, assessmentType: string): JsonMap {
  const values = scope
    .split(/[,\n]/)
    .map((item) => item.trim())
    .filter(Boolean);
  const targetMap: Record<string, string[]> = {
    urls: [],
    domains: [],
    cidr_ranges: [],
    ip_addresses: [],
    hosts: [],
    api_base_urls: [],
  };
  for (const value of values) {
    if (isUrl(value)) {
      if (assessmentType.toLowerCase().includes('api')) targetMap.api_base_urls.push(value);
      else targetMap.urls.push(value);
    } else if (isCidr(value)) {
      targetMap.cidr_ranges.push(value);
    } else if (isIp(value)) {
      targetMap.ip_addresses.push(value);
    } else if (isDomain(value)) {
      targetMap.domains.push(value);
    } else {
      targetMap.hosts.push(value);
    }
  }
  return Object.fromEntries(Object.entries(targetMap).filter(([, list]) => list.length > 0));
}

function inventorySeedData(targetMap: JsonMap, assessmentType: string): JsonMap {
  const hosts = [
    ...stringArray(targetMap.domains),
    ...stringArray(targetMap.ip_addresses),
    ...stringArray(targetMap.hosts),
    ...stringArray(targetMap.cidr_ranges),
  ];
  const urls = [...stringArray(targetMap.urls), ...stringArray(targetMap.api_base_urls)];
  return {
    hosts,
    urls,
    endpoints: urls.map((url) => ({ url, methods: [], status_code: null, title: 'React v2 intake target' })),
    api_types: stringArray(targetMap.api_base_urls).map((url) => ({ type: 'rest', base_url: url, confidence: 0.7 })),
    confidence: 0.72,
    assessment_type: assessmentType,
  };
}

function targetKind(value: string): string {
  if (!value.trim()) return 'Awaiting target';
  const first = value.split(/[,\n]/).map((item) => item.trim()).find(Boolean) || '';
  if (isUrl(first)) return 'URL';
  if (isCidr(first)) return 'CIDR';
  if (isIp(first)) return 'IP address';
  if (isDomain(first)) return 'Domain';
  return 'Host or custom target';
}

function firstTargetValue(targetMap: JsonMap): string {
  for (const value of Object.values(targetMap)) {
    const entries = stringArray(value);
    if (entries[0]) return entries[0];
  }
  return '';
}

function describesFullPentest(value: string): boolean {
  return (
    value.includes('full pentest') ||
    value.includes('volle pentest') ||
    value.includes('volledige pentest') ||
    value.includes('complete pentest') ||
    value.includes('all phases') ||
    value.includes('alle fases') ||
    (value.includes('full') && value.includes('pentest')) ||
    (value.includes('vol') && value.includes('pentest'))
  );
}

function describesActiveScan(value: string): boolean {
  return (
    value.includes('active scan') ||
    value.includes('actieve scan') ||
    value.includes('active scanning') ||
    value.includes('actief scannen')
  );
}

function describesPassiveScan(value: string): boolean {
  return value.includes('passive') || value.includes('passief') || value.includes('reconnaissance');
}

function humanizeDepth(value: string): string {
  const normalized = value.toLowerCase();
  if (describesFullPentest(normalized)) return 'Full Pentest';
  if (describesActiveScan(normalized)) return 'Active Scan';
  return 'Passive';
}

function humanizeGoal(value: string): string {
  const normalized = value.toLowerCase();
  if (describesFullPentest(normalized)) return 'Full Pentest';
  if (normalized.includes('inventory') || normalized.includes('overview')) return 'Passive';
  if (normalized.includes('standard') || describesActiveScan(normalized)) return 'Active Scan';
  return value || 'Passive';
}

function humanizeSafety(value: string): string {
  if (value.includes('conservative')) return 'Conservative and low-impact';
  return value || 'Operator-reviewed';
}

function isUrl(value: string): boolean {
  return /^https?:\/\//i.test(value);
}

function isCidr(value: string): boolean {
  return /^\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2}$/.test(value);
}

function isIp(value: string): boolean {
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(value);
}

function isDomain(value: string): boolean {
  return /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(value);
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : [];
}

function stringValue(value: unknown): string {
  return typeof value === 'string' ? value : '';
}

function errorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  return 'AegisPT request failed.';
}
