import re

# 1. Update Intake.tsx
intake_file = "src/components/Intake.tsx"
with open(intake_file, "r") as f:
    content = f.read()

# Replace main grid gap
content = content.replace(
    '<div className="flex h-full w-full min-h-0 gap-5">',
    '<div className="flex h-full w-full min-h-0 flex-col gap-0">'
)

# Replace the block that renders MissionProfile
old_block = """          </AnimatePresence>
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
      </div>"""

new_block = """          </AnimatePresence>
          <InlineContextStrip
            mission={mission}
            authorizationConfirmed={authorizationConfirmed}
            setAuthorizationConfirmed={setAuthorizationConfirmed}
            canLaunch={canLaunch}
            isLaunching={isLaunching}
            launchError={launchError}
            onLaunch={() => void launchMission()}
          />
        </div>
      </div>"""

if old_block in content:
    content = content.replace(old_block, new_block)
else:
    print("Failed to replace MissionProfile invocation in Intake.tsx")

# Replace MissionProfile definition
try:
    mission_profile_def = re.search(r'function MissionProfile\(\{.*?</aside>\s*\n\}', content, flags=re.DOTALL).group(0)

    inline_context_strip = """function InlineContextStrip({
  mission,
  authorizationConfirmed,
  setAuthorizationConfirmed,
  canLaunch,
  isLaunching,
  launchError,
  onLaunch,
}: {
  mission: MissionSummary;
  authorizationConfirmed: boolean;
  setAuthorizationConfirmed: (value: boolean) => void;
  canLaunch: boolean;
  isLaunching: boolean;
  launchError: string | null;
  onLaunch: () => void;
}) {
  const confirmedItems = [
    { label: 'Goal', value: mission.targetType },
    { label: 'Scope', value: mission.scope },
    { label: 'Safety', value: mission.safety },
  ].filter((item) => item.value);

  if (confirmedItems.length === 0) return null;

  const allConfirmed = Boolean(mission.targetType && mission.scope && mission.depth && mission.safety);

  return (
    <div className="shrink-0 border-t border-border bg-[rgba(5,9,18,0.9)] p-4 flex flex-wrap items-center justify-between gap-4">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-[0.85rem] font-bold uppercase tracking-widest text-muted mr-2">Mission Context:</span>
        {confirmedItems.map((item) => (
          <span key={item.label} className="rounded-full border border-cyan/30 bg-cyan/10 px-3 py-1 text-[0.85rem] font-semibold text-cyan">
            {item.label}: {item.value}
          </span>
        ))}
      </div>

      {allConfirmed && (
        <div className="flex flex-wrap items-center gap-4">
          <label className="flex items-center gap-2 text-[0.925rem] text-text cursor-pointer hover:text-cyan transition-colors">
            <input
              type="checkbox"
              checked={authorizationConfirmed}
              onChange={(event) => setAuthorizationConfirmed(event.target.checked)}
              className="accent-cyan"
            />
            Confirm authorization
          </label>
          <button
            type="button"
            disabled={!canLaunch}
            onClick={onLaunch}
            className="flex items-center justify-center gap-2 rounded-md bg-cyan px-4 py-2 text-sm font-bold text-[#04080f] shadow-[0_0_15px_rgba(94,207,255,0.3)] transition-all hover:shadow-[0_0_20px_rgba(94,207,255,0.5)] disabled:cursor-not-allowed disabled:opacity-40"
          >
            Create Mission
          </button>
        </div>
      )}
      {launchError && <div className="text-[0.85rem] text-red mt-2 w-full">{launchError}</div>}
    </div>
  );
}"""

    content = content.replace(mission_profile_def, inline_context_strip)
except AttributeError:
    print("Failed to replace MissionProfile definition in Intake.tsx")

with open(intake_file, "w") as f:
    f.write(content)

# 2. Update index.css
css_file = "src/index.css"
with open(css_file, "r") as f:
    css_content = f.read()

if ".finding-drawer" not in css_content:
    new_css = """
  .finding-drawer {
    position: fixed;
    right: 0;
    top: 48px;
    width: 420px;
    height: calc(100vh - 48px);
    background: var(--surface);
    border-left: 1px solid var(--border);
    overflow-y: auto;
    transform: translateX(100%);
    transition: transform 0.25s cubic-bezier(0.4, 0, 0.2, 1);
    z-index: 150;
    box-shadow: -4px 0 24px rgba(0,0,0,0.4);
  }
  .finding-drawer.open {
    transform: translateX(0);
  }
"""
    css_content = css_content.replace("@layer utilities {", "@layer utilities {" + new_css)
    with open(css_file, "w") as f:
        f.write(css_content)

# 3. Update FindingsTheater.tsx
findings_file = "src/components/screens/FindingsTheater.tsx"
with open(findings_file, "r") as f:
    f_content = f.read()

# Replace grid
f_content = f_content.replace(
    "xl:grid-cols-[55fr_45fr]'",
    "xl:grid-cols-1'"
)

f_content = f_content.replace(
    "<FindingDrawer",
    "<FindingDrawer open={true}"
)

# Use regex to find FindingDrawer definition and update props
try:
    f_content = re.sub(
        r'function FindingDrawer\(\{.*?\}\) \{',
        lambda m: m.group(0).replace('onJira: () => void;', 'onJira: () => void;\n  open?: boolean;'),
        f_content,
        flags=re.DOTALL
    )

    f_content = re.sub(
        r' className="flex h-full min-h-0 flex-col overflow-hidden rounded-xl border border-border bg-surface/50 backdrop-blur-md"',
        ' className={cn("finding-drawer", open && "open")}',
        f_content
    )
except Exception as e:
    print("Failed to replace FindingDrawer in FindingsTheater.tsx:", e)

with open(findings_file, "w") as f:
    f.write(f_content)

print("Redesign files updated.")
