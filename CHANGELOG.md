# Changelog

## [1.11.0] - 2026-11-09

### Added

- Public signed releases following HMDG's existing prerelease, canary and manual-promotion workflow.
- A native WordPress updater scoped to HMDG Security Pro, with no updater network, database or cookie work on ordinary visitor requests.
- Independent Ed25519 signing and fail-closed verification of the exact release bytes, plugin folder and declared version.
- Reproducible runtime-only packaging, version checks and behavioural regression tests.

### Changed

- Promoted newer releases can install through WordPress background updates once an existing site has received the one-time updater bootstrap.
- A dedicated Update URI prevents WordPress.org slug matching. Native installer rollback and activation handling are preserved, and failed-update emails remain enabled.

### Requirements

- WordPress 6.4+, PHP 8.2+, sodium and ZIP support. Prereleases do not install automatically; hosting restrictions, cron and API availability still apply.
