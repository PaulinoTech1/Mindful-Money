# Mindful Money error-code scheme

Every non-success JSON API response has this shape:

```json
{
  "error": "Readable, non-sensitive explanation.",
  "error_code": "MM_SERVER_ZKP_CHALLENGE_CREATE_BARRETENBERG_EXECUTABLE_OR_VERIFICATION_KEY_UNAVAILABLE"
}
```

The browser app appends the code to errors it displays. Network and client-side
ZKP failures receive a client-originated code when no server response exists.

## Grammar

```text
MM_<EXECUTION_SIDE>_<DOMAIN>_<OPERATION>_<CONDITION>
```

- `MM` identifies Mindful Money.
- `EXECUTION_SIDE` is `CLIENT` or `SERVER`, identifying where the failure was
  first classified. It does not assign blame to the user or infrastructure.
- `DOMAIN` identifies the likely subsystem, such as `HTTP`, `SECURITY`,
  `AUTHORIZATION`, `PASSKEY`, `VAULT`, `BANK`, `DATABASE`, `NETWORK`, or `ZKP`.
- `OPERATION` names what was being attempted. Additional uppercase segments may
  narrow the component or stage, such as `BARRETENBERG_VERIFY`.
- `CONDITION` is a stable diagnosis such as `SYNTAX_INVALID`,
  `MAXIMUM_SIZE_EXCEEDED`, `AUTHENTICATION_REQUIRED`, or
  `CRYPTOGRAPHIC_PROOF_REJECTED`.

Codes contain only uppercase ASCII letters, digits, and underscores. They are
stable identifiers; changing readable wording must not change a code. A changed
meaning requires a new code.

## Security rules

1. Codes identify a layer and failure class, never a secret value.
2. Authentication and challenge lookup codes remain deliberately ambiguous when
   precision would reveal whether another tenant, credential, or challenge
   exists. For example:
   `MM_SERVER_ZKP_CHALLENGE_CONSUME_UNAVAILABLE_EXPIRED_USED_OR_NOT_OWNED`.
3. Responses never include proof bytes, public-input values, ciphertext,
   credentials, filesystem paths, command output, or database details.
4. Server logs may record the code and an existing pseudonymous client reference,
   but must not add the rejected sensitive value.
5. HTTP status communicates transport semantics; `error_code` communicates the
   likely component and cause. Clients must not make authorization decisions from
   either value.

## ZKP examples

| Error code | Likely origin |
|---|---|
| `MM_SERVER_ZKP_CHALLENGE_CREATE_BARRETENBERG_EXECUTABLE_OR_VERIFICATION_KEY_UNAVAILABLE` | Challenge creation stopped because the pinned verifier executable or VK is unavailable. |
| `MM_CLIENT_ZKP_PROVER_MODULE_LOAD_BUNDLE_OR_WASM_UNAVAILABLE` | Browser could not load the proof bundle or its WASM dependencies. |
| `MM_CLIENT_ZKP_PROOF_GENERATE_WITNESS_OR_BARRETENBERG_EXECUTION_FAILED` | Browser witness execution or proof generation failed before submission. |
| `MM_SERVER_ZKP_MANUAL_TRANSACTION_PUBLIC_INPUTS_ENCODING_INVALID` | Submitted public inputs were malformed or non-canonical. |
| `MM_SERVER_ZKP_MANUAL_TRANSACTION_PUBLIC_CONTEXT_OR_CIRCUIT_VERSION_MISMATCH` | Public inputs did not match the server-issued challenge context or pinned circuit. |
| `MM_SERVER_ZKP_BARRETENBERG_VERIFY_EXECUTABLE_OR_VERIFICATION_KEY_UNAVAILABLE` | Runtime verification could not start because its server-owned dependency was unavailable. |
| `MM_SERVER_ZKP_BARRETENBERG_VERIFY_PROOF_STRUCTURE_OR_EXECUTION_INVALID` | Proof structure was invalid, verification timed out, or the verifier could not safely complete. |
| `MM_SERVER_ZKP_BARRETENBERG_VERIFY_CRYPTOGRAPHIC_PROOF_REJECTED` | Barretenberg completed and rejected the proof cryptographically. |

When troubleshooting, search the exact code in source and logs. Do not replace a
specific code with a generic status-based code merely to simplify UI handling.
