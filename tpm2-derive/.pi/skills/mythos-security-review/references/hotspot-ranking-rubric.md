# Hotspot Ranking Rubric

Score files, directories, or subsystems from 1 to 5.

## Score 5 — Highest priority
Strongly exposed and complex security boundaries.
Examples:
- network-facing parsers
- request authentication/authorization
- unsafe/native/FFI code
- deserialization
- sandbox, kernel, or VM boundaries
- crypto protocol state machines

## Score 4 — High priority
Indirectly exposed or high-impact internal components.
Examples:
- session handling
- permission checks
- object lifecycle code
- memory ownership transitions
- caching layers with trust assumptions

## Score 3 — Medium priority
Potentially relevant support code.
Examples:
- helpers used by exposed code
- validation layers
- conversion utilities
- error handling with security implications

## Score 2 — Low priority
Mostly supporting code with limited direct attack surface.
Examples:
- internal formatting helpers
- ordinary business logic with little privilege impact

## Score 1 — Minimal priority
Little or no direct security value.
Examples:
- constants-only files
- documentation
- trivial wrappers
- generated code with no meaningful local logic

## Boost signals
Increase priority when the code:
- handles untrusted bytes or structured input
- crosses trust or privilege boundaries
- uses `unsafe`, raw pointers, JNI, ctypes, or custom allocators
- contains “TODO”, “FIXME”, “should never happen”, or commented-out checks
- performs custom parsing, canonicalization, or normalization
- mixes security decisions with complex state

## Split strategy
Rank first, then cluster by:
- parser family
- auth family
- unsafe/native family
- crypto family
- privilege boundary family
