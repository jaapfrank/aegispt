import re

intake_file = "src/components/Intake.tsx"
with open(intake_file, "r") as f:
    content = f.read()

content = re.sub(r'function SummaryCard\(\{.*?</motion\.div>\s*\n\}', '', content, flags=re.DOTALL)

with open(intake_file, "w") as f:
    f.write(content)
