# Security Policy

## Protect API Keys

Never commit `.env` or any file containing real API keys. Use `.env.example` to document required environment variables.

If a key is accidentally committed, revoke it immediately from the provider portal and generate a new one.

## Local Data

CTI Agent 2 stores investigation data locally:

- `data/cti_agent2.db`
- `data/analyses`
- `data/exports`

These files may contain indicators, analysis results, case notes, or operational context. They are intentionally excluded from Git.

## Responsible Use

The tool is designed for defensive cyber threat intelligence, triage, reporting, and case workflow management. Do not use it to enable unauthorized access, exploitation, or harmful activity.
