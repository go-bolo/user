---
name: docs-plan
version: 1.3.0
description: Create, edit, refine, and explore change plans collaboratively with the user, grounding decisions in existing code, docs, and external references.
---

# docs-plan

Create, edit, refine, or explore a change plan in `docs/<feature>/<changesDir>/` together with the user. The skill acts as a planning partner: it gathers context from the existing codebase, feature documentation, and the web when useful, drafts or updates the plan, and iterates until the user explicitly approves.

## Input

The user provides one of the following:

- A new change description (e.g., "Create a mobile product UI for customers").
- A request to edit or refine an existing plan (e.g., "Update the plan for `products-store/ui-mobile-de-produtos-para-clientes`").
- A request to explore possibilities for a feature or change (e.g., "What are the options for improving the product catalog?").

## Workflow

### 1. Load configuration

Read the `config.docs` object in `.docd.json` to resolve `root`, `specFile`, `guideFile`, `uiFile`, `changelogFile`, `changesDir`, `archiveDir`, `changeFilenamePattern`, `defaultStatus`, and `allowedStatuses`. A `null` value for `specFile`, `guideFile`, or `uiFile` means the file is disabled: never create, read, update, or link to it.

### 2. Identify the target feature and change

- If the user provided a feature ID, use it.
- If the user provided a change ID, locate the existing plan file.
- If neither is provided, infer a feature name from the change description and ask the user to confirm or correct it. Example: "UI mobile de produtos para clientes" → feature `products-store` or `produtos`.
- If the feature directory does not exist, create it.

### 3. Gather context

Before writing or editing, collect relevant information:

- **Existing feature docs**: Read `docs/<feature-id>/<guideFile>`, `docs/<feature-id>/<specFile>`, `docs/<feature-id>/<uiFile>`, and `docs/<feature-id>/<changelogFile>` if they are configured (not `null`) and exist.
- **Existing plans**: Read the current plan file if editing or refining. Scan related plans in the same `changesDir/`.
- **Current code**: Use `grep`, `semantic_search`, and `read` to inspect relevant code paths when the user mentions concrete areas (e.g., `server/api`, `client/dashboard`). Summarize findings only; do not modify code.
- **External references**: Use `webfetch` when the user asks for industry patterns, library documentation, or competitive references that can inform the plan.

Present a brief summary of what was found before proposing changes, so the user can correct assumptions.

### 4. Create or update the feature structure if missing

When creating a new feature or subfeature, generate the following files with concise placeholders (skip any file disabled (`null`) in the config):

- `docs/<feature-id>/<guideFile>` (e.g., `guide.md`): description, how to use, goals, links.
- `docs/<feature-id>/<specFile>` (e.g., `spec.md`): technical vision, architecture, API contracts, flows, design decisions.
- `docs/<feature-id>/<uiFile>` (e.g., `ui.md`, optional): visual details, colors, formats, typography, and URL to an external design system (e.g., Figma).
- `docs/<feature-id>/<changelogFile>` (e.g., `changelog.md`): empty table with columns Date, Change, Description, Responsible.
- `docs/<feature-id>/<changesDir>/` directory.

### 5. Generate or update the change plan

- Convert the change title to `kebab-case` for the change ID. Example: "UI mobile de produtos para clientes" → `ui-mobile-de-produtos-para-clientes`.
- Ensure the change ID is unique in `docs/<feature-id>/<changesDir>/`.
- Draft or update the plan file at `docs/<feature-id>/<changesDir>/<date>-<change-id>-plan.md` using the configured `changeFilenamePattern`. Use today's date for `<date>` (e.g., `2026-07-09`).
- Include YAML frontmatter: `id`, `feature_id`, `title`, `status`, `priority`, `created_at`, `updated_at`.
- Include sections: Contexto, Objetivos, Especificação Técnica, Tarefas, Verificação.
- Leave all task checkboxes as `- [ ]`.

When editing an existing plan, preserve the existing `id` and `created_at`, update only what changed, and refresh `updated_at`.

### 6. Present the plan to the user

Show a concise summary including:

- Feature ID and change ID.
- Plan title and priority.
- Main objectives.
- Key findings from the context gathering (code, docs, web).
- Number of tasks.
- Full path to the plan file.
- Highlight what changed compared to the previous version when editing.

### 7. Collect feedback and refine iteratively

Ask the user: **"Aprove this plan as-is, request changes, explore alternatives, or cancel?"**

- If the user **approves explicitly** (e.g., "aprovar", "approved", "ok", "proceed"), save the plan as-is and recommend executing it in a **new conversation or session** using `/docs-implement <feature-id>/<change-id>` to keep context isolated.
- If the user requests changes, ask what to adjust (scope, tasks, priority, affected areas, technical approach, etc.). Update the plan file accordingly and present the revised version. Repeat this step until explicit approval.
- If the user wants to explore alternatives, present 2–3 concise options with trade-offs, grounded in the gathered context. After the user chooses, update the plan and continue refining.
- If the user cancels, remove the draft plan file (and the feature directory if it was created just for this plan and is empty) and stop.

### 8. After approval

- Mark the plan status as `pending` (ready for development) and update `updated_at`.
- Output a clear message: "Plan approved and saved at <path>. To keep the current context clean, start implementing this plan in a new conversation or session using `/docs-implement <feature-id>/<change-id>`."

## Output

- Path of the approved or updated plan file.
- Recommendation to continue implementation in a new conversation/session using `/docs-implement <feature-id>/<change-id>`.

## Guardrails

- Do not overwrite existing files unless the user explicitly asks to edit an existing plan.
- Always use the configured paths from `config.docs` in `.docd.json`.
- Never create files disabled (`null`) in `config.docs`.
- Always ask for or confirm the feature name when creating a plan for a non-existing feature.
- Do not proceed to implementation without explicit user approval of the plan.
- If the user requests refinements, update the same plan file and re-present the summary.
- Keep content concise and technical.
- When gathering context, do not modify code or non-docs files.
- When using external references, cite the source briefly and only use them to inform the plan, not to override project conventions.
