# Security Policy

## Reporting a vulnerability

Please don't open a public GitHub issue for a security finding — file it
privately instead:

- **Preferred:** use GitHub's private vulnerability reporting (Security tab
  → "Report a vulnerability" on this repo). It creates a private advisory
  visible only to maintainers until a fix is ready.
- **Alternative:** email opensecmcp@aivare.ai with a clear subject line
  indicating this is a security report.

Include, if you can:
- What you did, and what you expected the gateway to do instead.
- The actual tool response or config that triggered the gap, if possible
  as a minimal reproduction rather than something tied to a real system.
- Which guarantee in `THREAT_MODEL.md` this breaks, if you're not sure
  whether something is in-scope or a known, stated limitation — when in
  doubt, report it and let us make that call rather than assuming it's
  already known.

## Scope

`THREAT_MODEL.md` describes what this project claims to defend against.
A report that something *listed there as defended against* fails in
practice is a real vulnerability. A report about something the threat
model already states as an explicit limitation is still useful — it may
mean the limitation needs to be more prominent, or the fix has become
worth prioritizing — but it isn't a surprise finding, and won't be treated
as urgent the way a broken guarantee would be.

## What to expect

This is maintained without a dedicated security team, so there's no fixed
response-time commitment — reports get real attention, on a best-effort
basis, not a form-letter delay. Coordinated disclosure is appreciated:
please give us a chance to ship a fix before any public write-up, and
we'll work with you on timing rather than asking for an open-ended
embargo.

## Supported versions

Pre-1.0: only the latest commit on `main` is supported. There is no
backport policy yet.
