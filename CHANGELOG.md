# Changelog

This file documents recent notable changes to this project. The format of this
file is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- The runtime release-trust accept path, which judges a delivered generation
  against the **active** generation's trust set and applies the `epoch` floor:
  `release_trust::accept_generation` for one delivered generation,
  `release_trust::accept_generation_chain` for the ordered replay that catches a
  lagging host up, and `release_trust::read_generation_state` for the question a
  caller asks before it pushes. A byte-identical redelivery of the active
  generation is an unchanged no-op rather than a refusal; anything else must be
  strictly newer than the active generation to activate.

[Unreleased]: https://github.com/aicers/deploy-core/commits/main
