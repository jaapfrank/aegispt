import re

with open("ui-v2/src/components/Intake.tsx", "r") as f:
    content = f.read()

# 1. Remove IntakeMode
content = re.sub(r"type IntakeMode = 'ai' \| 'wizard';\n", "", content)

# 2. Add showLaunchCeremony state
content = re.sub(
    r"const \[isLaunching, setIsLaunching\] = useState\(false\);",
    "const [isLaunching, setIsLaunching] = useState(false);\n  const [showLaunchCeremony, setShowLaunchCeremony] = useState(false);",
    content
)

# 3. Remove mode state
content = re.sub(
    r"const \[mode, setModeState\] = useState<IntakeMode>\(\(\) => {[\s\S]*?}\);\n",
    "",
    content
)

# 4. Remove setMode function
content = re.sub(
    r"  function setMode\(nextMode: IntakeMode\) {[\s\S]*?}\n\n",
    "",
    content
)

# 5. Update launchMission
launch_mission_old = r"async function launchMission\(source: 'ai' \| 'wizard'\) \{\n    if \(\!missionReady \|\| \!authorizationConfirmed \|\| isLaunching\) return;\n    setIsLaunching\(true\);\n    setLaunchError\(null\);\n    setError\(null\);\n    try \{"
launch_mission_new = """async function launchMission() {
    if (!missionReady || !authorizationConfirmed || isLaunching) return;
    setIsLaunching(true);
    setLaunchError(null);
    setError(null);
    setShowLaunchCeremony(true);
    await new Promise((resolve) => setTimeout(resolve, 2000));
    try {"""
content = content.replace(
    "async function launchMission(source: 'ai' | 'wizard') {\n    if (!missionReady || !authorizationConfirmed || isLaunching) return;\n    setIsLaunching(true);\n    setLaunchError(null);\n    setError(null);\n    try {",
    launch_mission_new
)
content = content.replace("`React v2 intake source: ${source}`", "`React v2 intake source: split-path`")
content = content.replace("() => void launchMission(mode)", "() => void launchMission()")

# 6. Update the main return block
main_return_old = r"  return \([\s\S]*?  \);\n}"
main_return_new = """  return (
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

      <div className="grid h-full w-full gap-5 xl:grid-cols-[minmax(0,1fr)_340px]">
        <div className="grid min-h-[680px] flex-1 overflow-hidden rounded-xl border border-border bg-[rgba(12,21,36,0.4)] shadow-2xl backdrop-blur-md lg:grid-cols-2">
          {/* AI Intake Side */}
          <div className="flex flex-col border-r border-border/50">
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border bg-[rgba(5,9,18,0.65)] p-4">
              <div className="flex items-center gap-2 text-xs font-bold text-cyan">
                <Sparkles size={14} />
                AI Intake
              </div>
              <span className="flex items-center gap-2 text-[11px] font-mono uppercase tracking-widest text-cyan/70">
                <span className="h-1.5 w-1.5 rounded-full bg-cyan animate-pulse" />
                Backend connected
              </span>
            </div>
            <AiIntakePane
              messages={messages}
              isTyping={isTyping}
              inputValue={inputValue}
              setInputValue={setInputValue}
              handleSend={handleSend}
              messagesEndRef={messagesEndRef}
            />
          </div>

          {/* Manual Wizard Side */}
          <div className="flex flex-col bg-[rgba(12,21,36,0.2)]">
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border bg-[rgba(5,9,18,0.65)] p-4">
              <div className="flex items-center gap-2 text-xs font-bold text-muted">
                <SlidersHorizontal size={14} />
                Manual Wizard
              </div>
            </div>
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
          </div>
        </div>

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
}"""
content = re.sub(main_return_old, main_return_new, content, count=1)

# 7. Add 3D flips to WizardPane tiles
tile_return_new = """return (
                <div key={tile.key} className="group relative min-h-[156px] [perspective:1000px]">
                  <button
                    type="button"
                    onClick={() => onTileSelect(tile)}
                    data-testid={`wizard-assessment-tile-${tile.key}`}
                    aria-pressed={selected}
                    className={cn(
                      'relative h-full w-full text-left transition-all duration-500 [transform-style:preserve-3d]',
                      selected ? '[transform:rotateY(180deg)]' : 'hover:-translate-y-1'
                    )}
                  >
                    <div className={cn(
                      'absolute inset-0 flex flex-col rounded-lg border border-border bg-surface/45 p-4 [backface-visibility:hidden]',
                    )}>
                      <div className="mb-3 flex items-center justify-between gap-3">
                        <span className="flex h-9 w-9 items-center justify-center rounded-md border border-cyan/20 bg-cyan/10 text-cyan">
                          <Icon size={17} />
                        </span>
                        {tile.badge && (
                          <span className="rounded-full border border-border bg-bg/70 px-2 py-0.5 text-[10px] font-bold uppercase text-muted">
                            {tile.badge}
                          </span>
                        )}
                      </div>
                      <div className="text-[13px] font-semibold text-text">{tile.label}</div>
                      <p className="mt-2 line-clamp-3 text-[12px] leading-5 text-muted">{tile.description}</p>
                    </div>

                    <div className={cn(
                      'absolute inset-0 flex flex-col rounded-lg border border-cyan/50 bg-cyan/10 p-4 shadow-[0_0_18px_rgba(94,207,255,0.12)] [backface-visibility:hidden] [transform:rotateY(180deg)]',
                    )}>
                      <div className="mb-3 flex items-center justify-between gap-3">
                        <span className="flex h-9 w-9 items-center justify-center rounded-md border border-cyan/50 bg-cyan/20 text-cyan">
                          <CheckCircle2 size={17} />
                        </span>
                      </div>
                      <div className="text-[13px] font-semibold text-cyan">{tile.label} Selected</div>
                      <div className="mt-auto flex flex-wrap gap-1.5">
                        {tile.phaseTags.map((tag) => (
                          <PhaseTag key={`${tile.key}-${tag.label}`} label={tag.label} tone={tag.tone} />
                        ))}
                      </div>
                    </div>
                  </button>
                </div>
              );
            });"""
content = re.sub(r"return \(\s*<button\s*key=\{tile\.key\}[\s\S]*?</button>\s*\);\s*\}\);", tile_return_new, content)

with open("ui-v2/src/components/Intake.tsx", "w") as f:
    f.write(content)

print("Patch applied to Intake.tsx")
