# SPEC-0083 — MCP Method Canonical Alphabet

**Status:** PROPOSED → implementation-qualified in the same security branch  
**Context:** findings from the authorized, loopback-only multi-agent red-team laboratory

## 1. Problem

A policy gateway must classify the exact protocol message that the upstream will parse. SPEC-0081/0082 already made strict JSON and the JSON-RPC body authoritative, but live adversarial testing found a remaining parser-differential class in method names: finite normalization of selected slash variants cannot enumerate Unicode confusables, double percent-encoding, zero-width characters, controls, or future look-alikes.

Examples observed in the sandbox include `tools／call`, `tools﹨call`, `tools＼call`, `tools%252Fcall`, `tools/call<ZWSP>`, `tools/<ZWSP>call`, and a NUL-suffixed method. A strict upstream treats these as unknown methods, but a permissive or normalizing upstream could reinterpret one as `tools/call` after the gateway had already classified it as ordinary passthrough traffic.

## 2. Security invariant

The gateway SHALL NOT attempt to recognize every visual or encoded confusable. It SHALL establish a canonical transport alphabet for MCP JSON-RPC method names before classification or forwarding.

A method is canonical only when:

- it is non-empty;
- its UTF-8 byte length is at most 128;
- every byte is ASCII alphanumeric or one of `/`, `_`, `-`, `.`.

Anything else is rejected before the upstream with HTTP 400 and `MCP_METHOD_INVALID`.

This intentionally rejects Unicode, percent signs, reverse slashes, whitespace, ASCII controls, zero-width characters, and other punctuation in method names. Standard MCP methods such as `initialize`, `ping`, `tools/list`, `tools/call`, `resources/read`, and `prompts/get` remain valid.

## 3. Ordering

The boundary is:

1. strict JSON validation (duplicate keys / malformed / excessive ambiguity fail closed);
2. extract the body-authoritative JSON-RPC method;
3. canonical-alphabet validation;
4. exact `tools/call` classification and policy evaluation;
5. ordinary canonical MCP methods may follow the configured passthrough behavior.

Caller-controlled helper headers do not participate in classification and are not forwarded upstream.

## 4. Regression matrix

Permanent tests SHALL cover at least:

- `tools/call` accepted by the canonical-alphabet predicate;
- `tools/list`, `resources/read`, `prompts/get`, `ping` accepted;
- fullwidth solidus U+FF0F rejected;
- small reverse solidus U+FE68 rejected;
- fullwidth reverse solidus U+FF3C rejected;
- double-encoded slash text `%252F` rejected;
- zero-width U+200B rejected;
- NUL / ASCII controls rejected;
- whitespace rejected;
- backslash rejected;
- over-128-byte method rejected.

The live sandbox matrix must additionally prove `upstream_delta = 0` for all rejected variants.

## 5. Non-goals

This SPEC does not make non-tool MCP methods policy-controlled. `resources/read`, `prompts/get`, `tools/list`, and other canonical non-tool methods remain a separate policy/observability decision. It only guarantees they cannot be reached through an ambiguous method spelling.

## 6. Acceptance

Qualified when focused Agent/Gateway tests pass, Clippy is clean, a release build is produced, and the loopback-only sandbox campaign demonstrates zero upstream forwards for the confusable/encoding matrix while preserving normal `tools/call` enforcement and ordinary canonical method behavior.
