#!/usr/bin/env node
// Postinstall hook.
// Intentionally silent and side-effect-free in ALL contexts:
//   - CI environments (CI=true)
//   - Non-TTY / piped / agent environments
//   - Production (NODE_ENV=production)
// No network calls, no file writes, no commercial URLs, no process.exit
// that could fail a build. Only prints a single non-URL hint on an
// interactive TTY so a human running `npm install` locally gets a reminder.

const isCI = !!process.env.CI;
const isProd = process.env.NODE_ENV === 'production';
const isTTY = process.stdout.isTTY === true;

if (isCI || isProd || !isTTY) process.exit(0);

// Local interactive use only — a single line, no URLs.
process.stdout.write(
  'supabase-security installed — run: npx supabase-security <project-ref>\n'
);
