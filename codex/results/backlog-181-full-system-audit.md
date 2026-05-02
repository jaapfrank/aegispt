# Backlog 149 Full System Acceptance Defect Inventory

- Generated: `2026-05-02T13:23:36.683691+00:00`
- Base URL: `http://127.0.0.1:8000`
- Duration: `9.82s`
- Screens visited/expected: `14/14`
- Defects recorded: `23`
- Safe field events: `49`

## API And Health

- `/health/live`: `200` ok=`True`
- `/api/v1/dashboard` status=`200` ok=`True`
- `/api/v1/settings` status=`200` ok=`True`
- `/api/v1/engagements` status=`200` ok=`True`
- `/api/v1/runs` status=`405` ok=`False`

## Defects

| Severity | Screen | Code | Evidence | Backlog |
| --- | --- | --- | --- | --- |
| high | `history` | `error_state_without_action` | The screen contains an error/unavailable state but no visible action was collected. | `backlog-152` (covered_by_existing_backlog) |
| medium | `custom-vulnerabilities` | `field_without_guidance` | A visible input/select/textarea had no label, placeholder, title, or aria-label. | `backlog-153` (covered_by_existing_backlog) |
| medium | `custom-vulnerabilities` | `field_without_guidance` | A visible input/select/textarea had no label, placeholder, title, or aria-label. | `backlog-153` (covered_by_existing_backlog) |
| medium | `custom-vulnerabilities` | `field_without_guidance` | A visible input/select/textarea had no label, placeholder, title, or aria-label. | `backlog-153` (covered_by_existing_backlog) |
| medium | `custom-vulnerabilities` | `field_without_guidance` | A visible input/select/textarea had no label, placeholder, title, or aria-label. | `backlog-153` (covered_by_existing_backlog) |
| medium | `custom-vulnerabilities` | `field_without_guidance` | A visible input/select/textarea had no label, placeholder, title, or aria-label. | `backlog-153` (covered_by_existing_backlog) |
| medium | `custom-vulnerabilities` | `field_without_guidance` | A visible input/select/textarea had no label, placeholder, title, or aria-label. | `backlog-153` (covered_by_existing_backlog) |
| medium | `custom-vulnerabilities` | `field_without_guidance` | A visible input/select/textarea had no label, placeholder, title, or aria-label. | `backlog-153` (covered_by_existing_backlog) |
| medium | `evidence-replay` | `placeholder_or_internal_copy` | Visible text contains 'nan'. | `backlog-152` (covered_by_existing_backlog) |
| medium | `history` | `field_without_guidance` | A visible input/select/textarea had no label, placeholder, title, or aria-label. | `backlog-153` (covered_by_existing_backlog) |
| medium | `history` | `field_without_guidance` | A visible input/select/textarea had no label, placeholder, title, or aria-label. | `backlog-153` (covered_by_existing_backlog) |
| medium | `pack-forge` | `disabled_action_without_reason` | Disabled action label='Validate Pack' has no nearby unlock reason. | `backlog-152` (covered_by_existing_backlog) |
| medium | `pack-forge` | `disabled_action_without_reason` | Disabled action label='Approve Pack' has no nearby unlock reason. | `backlog-152` (covered_by_existing_backlog) |
| medium | `pack-forge` | `disabled_action_without_reason` | Disabled action label='Deploy Pack' has no nearby unlock reason. | `backlog-152` (covered_by_existing_backlog) |
| medium | `pack-forge` | `field_without_guidance` | A visible input/select/textarea had no label, placeholder, title, or aria-label. | `backlog-153` (covered_by_existing_backlog) |
| medium | `pack-forge` | `field_without_guidance` | A visible input/select/textarea had no label, placeholder, title, or aria-label. | `backlog-153` (covered_by_existing_backlog) |
| medium | `pack-forge` | `field_without_guidance` | A visible input/select/textarea had no label, placeholder, title, or aria-label. | `backlog-153` (covered_by_existing_backlog) |
| medium | `pack-forge` | `field_without_guidance` | A visible input/select/textarea had no label, placeholder, title, or aria-label. | `backlog-153` (covered_by_existing_backlog) |
| medium | `settings` | `disabled_action_without_reason` | Disabled action label='Suggest from Inventory' has no nearby unlock reason. | `backlog-152` (covered_by_existing_backlog) |
| medium | `settings` | `disabled_action_without_reason` | Disabled action label='Save Schedule' has no nearby unlock reason. | `backlog-152` (covered_by_existing_backlog) |
| medium | `settings` | `disabled_action_without_reason` | Disabled action label='Refresh schedules' has no nearby unlock reason. | `backlog-152` (covered_by_existing_backlog) |
| medium | `settings` | `disabled_action_without_reason` | Disabled action label='Refresh' has no nearby unlock reason. | `backlog-152` (covered_by_existing_backlog) |
| medium | `settings` | `placeholder_or_internal_copy` | Visible text contains 'nan'. | `backlog-152` (covered_by_existing_backlog) |

## Screens

- `dashboard` visited=`True` heading=`Dashboard` controls=`1` fields=`0` text_length=`316`
- `wizard` visited=`True` heading=`What do you want to test?` controls=`20` fields=`0` text_length=`2257`
- `mission-control` visited=`True` heading=`Mission Control` controls=`7` fields=`0` text_length=`957`
- `agents` visited=`True` heading=`Live Agents` controls=`4` fields=`0` text_length=`261`
- `surface-map` visited=`True` heading=`Surface / Attack Map` controls=`7` fields=`0` text_length=`592`
- `problems-center` visited=`True` heading=`Problems Center` controls=`1` fields=`0` text_length=`246`
- `custom-vulnerabilities` visited=`True` heading=`Custom CVE Library` controls=`3` fields=`17` text_length=`1035`
- `findings-theater` visited=`True` heading=`Findings` controls=`4` fields=`0` text_length=`227`
- `report-center` visited=`True` heading=`Reports` controls=`2` fields=`0` text_length=`563`
- `history` visited=`True` heading=`Comparison & Next Steps` controls=`0` fields=`3` text_length=`577`
- `pack-forge` visited=`True` heading=`Pack Forge` controls=`4` fields=`10` text_length=`717`
- `evidence-replay` visited=`True` heading=`Evidence Replay` controls=`0` fields=`0` text_length=`640`
- `explorer` visited=`True` heading=`Explorer` controls=`2` fields=`0` text_length=`775`
- `settings` visited=`True` heading=`Settings` controls=`34` fields=`52` text_length=`15914`

## Backlog Crosscheck

| Backlog | Defects | Screens |
| --- | ---: | --- |
| `backlog-153` | 13 | custom-vulnerabilities, history, pack-forge |
| `backlog-152` | 10 | evidence-replay, history, pack-forge, settings |

## Safe Fill Evidence

- `wizard` clicked_safe_tile [data-testid="wizard-assessment-tile-internal-lan"]
- `wizard` advanced_to_target_step [data-testid="wizard-assessment-submit-selection"]
- `wizard` filled_safe_loopback_target [data-testid="wizard-target-input"]
- `wizard` selected_passive_depth [data-testid="wizard-depth-tile-passive"]
- `wizard` opened_preview_without_launch [data-wizard-preview="true"]
- `custom-vulnerabilities` skipped_no_stable_selector
- `custom-vulnerabilities` skipped_no_stable_selector
- `custom-vulnerabilities` filled_safe_value name=custom_id
- `custom-vulnerabilities` filled_safe_value name=title
- `custom-vulnerabilities` filled_safe_value name=description
- `custom-vulnerabilities` filled_safe_value name=cvss_score
- `custom-vulnerabilities` filled_safe_value name=cwe_ids
- `custom-vulnerabilities` filled_safe_value name=affected_products
- `custom-vulnerabilities` filled_safe_value name=linked_nuclei_template_ref
- `custom-vulnerabilities` filled_safe_value name=payload
- `history` filled_safe_value testid=history-search
- `pack-forge` filled_safe_value name=source
- `pack-forge` filled_safe_value name=advisory_id
- `pack-forge` fill_failed name=title
- `pack-forge` filled_safe_value name=summary
- `pack-forge` filled_safe_value name=product
- `pack-forge` filled_safe_value name=hint
- `pack-forge` filled_safe_value name=attack_surface_type
- `pack-forge` filled_safe_value name=severity
- `pack-forge` filled_safe_value name=patterns
- `settings` expanded_settings_panels
- `settings` skipped_no_stable_selector
- `settings` skipped_no_stable_selector
- `settings` skipped_no_stable_selector
- `settings` skipped_no_stable_selector
- `settings` skipped_no_stable_selector
- `settings` skipped_no_stable_selector
- `settings` skipped_no_stable_selector
- `settings` skipped_no_stable_selector
- `settings` skipped_no_stable_selector
- `settings` skipped_no_stable_selector
- `settings` skipped_no_stable_selector
- `settings` skipped_no_stable_selector
- `settings` skipped_no_stable_selector
- `settings` skipped_no_stable_selector
- `settings` skipped_no_stable_selector
- `settings` skipped_no_stable_selector
- `settings` skipped_no_stable_selector
- `settings` skipped_no_stable_selector
- `settings` skipped_no_stable_selector
- `settings` skipped_no_stable_selector
- `settings` skipped_no_stable_selector
- `settings` skipped_no_stable_selector
- `settings` skipped_no_stable_selector

## Notes

- Discovered 14 primary/navigation screens.
