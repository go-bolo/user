---
name: docs-sync
version: 1.3.0
description: Finalize an implemented change plan, update the changelog, and refresh feature documentation to reflect what was implemented.
---

# docs-sync

After implementation, finalize the change plan, update the feature/subfeature `changelog.md`, and refresh the enabled feature docs (`guide.md`, `spec.md`, `ui.md`) to reflect what was actually implemented.

## Input

- Feature ID, optionally with a change ID (e.g., `/docs-sync products-store` or `/docs-sync products-store/ui-mobile-de-produtos-para-clientes`).

## Steps

1. **Load configuration**

   Read the `config.docs` object in `.docd.json` to resolve `root`, `specFile`, `guideFile`, `uiFile`, `changelogFile`, `changesDir`, and `allowedStatuses`. A `null` value for `specFile`, `guideFile`, or `uiFile` means the file is disabled: never create, read, update, or link to it.

2. **Identify the target**

   - If a change ID is provided, process only that change plan.
   - If only a feature ID is provided, process all changes in `docs/<feature-id>/<changesDir>/` that are not yet synced to the changelog.

3. **Read the change plan and feature docs**

   - Read `docs/<feature-id>/<changesDir>/<date>-<change-id>-plan.md`.
   - Check the current `status` in the frontmatter.
   - Read `docs/<feature-id>/<guideFile>`, `docs/<feature-id>/<specFile>`, and `docs/<feature-id>/<uiFile>` — skip any that are disabled (`null`) in the config.

4. **Finalize the plan status**

   - If the status is not `completed` or `finalizado`, update it to `completed` and set `updated_at` to today.
   - Ensure all tasks are marked as `- [x]`. If any task is still unchecked, report it to the user and ask whether to proceed.

5. **Generate a summary of implementation**

   - Read the completed tasks and, if available, the related code changes (e.g., `git diff` since the plan was created).
   - Summarize what was implemented in one to two sentences.
   - Include the change ID, date, and responsible party (use the feature `owner` from `guideFile` frontmatter if available).

6. **Update the changelog**

   - Read `docs/<feature-id>/<changelogFile>`.
   - Append a new row to the table: Date, Change link, Description, Responsible.
   - Avoid duplicate entries for the same change ID.

7. **Refresh feature documentation**

   - Compare the implemented changes with the current enabled feature docs (`guide.md`, `spec.md`, `ui.md`).
   - Update the feature docs to reflect what was actually shipped:
     - Add or update sections in `spec.md` for new API contracts, flows, or architectural decisions (if enabled).
     - Add or update UI notes, screenshots, or links to external design systems (e.g., Figma) in `ui.md` (if enabled).
     - Update `guide.md` usage instructions, goals, or affected areas if they changed (if enabled).
   - Update `updated_at` in `guide.md` frontmatter (if enabled).
   - Keep edits concise and focused on what changed; do not rewrite unrelated docs.

8. **Update the index**

   - If the project uses an index file, ensure it reflects the new status. (If no index file is configured, skip this step.)

## Output

Report the changelog path and the entries added. If feature docs were updated, list which files changed. If a plan status was changed, report the new status.

## Guardrails

- Only update the changelog and docs of the target feature/subfeature, never a parent or sibling feature.
- Do not duplicate changelog entries.
- Keep changelog descriptions concise and focused on what was implemented.
- Do not invent implementation details; only update docs based on the completed plan and actual code changes.
- If no changes were completed, report that and do not modify the changelog or feature docs.
- Do not archive the plan; keep it in `changes/` for traceability.
