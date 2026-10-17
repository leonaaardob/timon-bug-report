# Timon Bug Report

[![Offline package checks](https://github.com/leonaaardob/timon-bug-report/actions/workflows/ci.yml/badge.svg)](https://github.com/leonaaardob/timon-bug-report/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Turn a Timon problem into a concise bug report and a privacy-reviewed evidence archive.

This [Agent Skills](https://agentskills.io/specification) skill guides an AI assistant through read-only investigation, evidence selection and report preparation. It works with supplied screenshots and logs, or with authorized access to the affected environment. English is the default; another language can be requested.

This is an independent community project, not an official Timon project. It prepares reports; it does not repair Timon or submit anything automatically.

## What you get

| Output | Purpose |
| --- | --- |
| `archive.zip` | Human-readable report, structured JSON and selected sanitized evidence. |
| `discord.md` | Copy-ready title, operating system, affected area and concise description matching the reporting form. |
| `archive.zip.sha256` | Archive integrity checksum. |
| `package-checks.json` | Checks performed and their limitations. |
| `owner-notes.md` | Optional private inventory or decisions, kept outside the public archive. |

The report distinguishes observations, user statements, hypotheses and proposed reproduction steps. Missing information stays explicit. Unrelated bugs are normally reported separately; related findings can share one incident report.

## Requirements

- An AI assistant that supports Agent Skills or can load `SKILL.md` and its referenced files.
- **Python 3.10+** to run the optional offline packaging helper. It uses the standard library only.
- Evidence of the problem, such as a description, screenshots or relevant log excerpts.

Access to a running Timon instance, SSH, a database or the network is optional. The assistant can prepare a report from supplied evidence alone. Installing this skill does not modify a Timon installation.

## Installation

Clone the repository:

```sh
git clone https://github.com/leonaaardob/timon-bug-report.git
```

Install the cloned `timon-bug-report` directory using your assistant client's documented skill installation method. Keep the directory intact: `references/` and `scripts/` are part of the skill. There is no single installation path shared by every client.

The entry point is [SKILL.md](SKILL.md). The optional `agents/openai.yaml` file provides UI metadata for clients that recognize it; the core workflow does not depend on that file or on a particular model provider.

## Usage

Ask your assistant to use the skill and describe the symptom. For example:

> Use timon-bug-report to investigate this Timon issue without changing the installation. Prepare a sanitized archive.zip and the English Discord form fields. Here is the symptom and the evidence I have: …

If your client supports explicit skill invocation, use its documented syntax. Supply the Timon version, affected operating system and provider/model when known. Do not include account credentials or full configuration exports.

The assistant should return the archive and these form fields:

- Title of the problem
- Operating system
- Feature or area concerned
- Describe the problem: Timon version, LLM provider/model, steps, expected result and actual result

Review the report and attachments before submitting them. The current reporting form takes precedence over the reference template in this repository.

## Package an approved report manually

The assistant normally prepares the files. You can also run the packaging helper yourself after reviewing a sanitized staging directory:

```text
artifacts/
├── public/
│   ├── BUG-REPORT.md
│   ├── report.json
│   └── evidence/         # Optional selected evidence
└── discord.md
```

From the skill directory:

```sh
python scripts/package_report.py --source artifacts/public --output artifacts/archive.zip
```

Use `python3` or `py -3` if that is your system's Python launcher. See [the report contract](references/report-contract.md) for the JSON structure and evidence requirements.

The helper validates report structure, checks common disclosure patterns, builds a ZIP under 10 MB, extracts it, repeats checks and verifies CRC and SHA-256. It refuses to overwrite existing output.

Optional flags:

| Flag | Purpose |
| --- | --- |
| `--denylist-file <file>` | Reject known private **nonsecret** identifiers, one per line. Keep this file outside `public/`. |
| `--reviewed-png evidence/<name>.png` | Include a visually reviewed PNG after removing textual/EXIF metadata. |

The helper is offline. It does not collect host data, anonymize files or send reports. PNG checks cover structure and metadata, not private information visible in the pixels.

## Privacy and permissions

Investigation is read-only by default. Repairs, restarts, destructive reproductions, paid model calls and public submission require separate authorization.

Public artifacts must exclude passwords, tokens, cookies, auth files, production databases, full logs/configurations, private prompts and unreviewed screenshots. Use consistent aliases to retain diagnostic relationships without publishing real identities. Keep any requested private inventory outside the ZIP.

Automated pattern scans cannot guarantee complete anonymization. Manual review remains required, including screenshot content and metadata. A passing package check also does not prove the bug was reproduced or fixed.

## Development and validation

Run the offline regression suite:

```sh
python -m unittest discover -s tests -v
```

It uses synthetic data and does not call a model or connect to Timon. Coverage includes schema validation, private text and filenames, authentication headers, archive integrity and reproducibility, unsafe paths, overwrite protection and PNG review/metadata checks.

[GitHub Actions](https://github.com/leonaaardob/timon-bug-report/actions/workflows/ci.yml) runs the suite on Linux, Windows and macOS with Python 3.10 and 3.13. Check the actual workflow results for platform status; tests that depend on unavailable filesystem capabilities may be skipped.

The skill follows the open [Agent Skills specification](https://agentskills.io/specification) and [authoring guidance](https://agentskills.io/skill-creation/best-practices). To validate its format with the reference package:

```sh
uvx --from skills-ref agentskills validate .
```

Agent behavior requires separate evaluation. [Synthetic evaluation scenarios](evals/scenarios.md) provide prompts and observable criteria for checking evidence fidelity, boundaries and handoff quality. Passing the Python suite is not an endorsement by Timon or an agent vendor, nor proof that every assistant or Timon version behaves correctly.

## Contributing

Bug reports and improvements are welcome through [Issues](https://github.com/leonaaardob/timon-bug-report/issues) and pull requests.

Use minimized synthetic fixtures. Never attach real credentials, production logs or a private alias mapping. For code changes, run the offline tests. When report fields or schema change, update the contract and affected tests together.

## License

[MIT](LICENSE).
