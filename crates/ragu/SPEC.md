# ragu SPEC

## Invariants

- Maybe
  - KindAlways: closures execute; storage present; operations allocate no extra state beyond T.
  - KindEmpty: closures do not execute; value operations are no-ops; size is ZST; `take()` must not be used by user code in non-witness paths; prefer `Present<T>` extraction.
- Driver
  - Proving mode (with-witness): `mul` closures execute; `add`/`enforce_zero` may avoid eager evaluation; `from_field` returns a wire representing a constant.
  - Verification/public-input modes (no-witness): `mul` closures do not execute; `add`/`enforce_zero` evaluate linear combinations over wire values; `from_field` returns the value-domain wire.
  - Circuits must treat `W` as opaque; do not branch on representation.
- Circuit
  - `input` maps instance to IO without mutating witness; `main` produces IO+Aux; `output` emits public inputs; identical `output` under witness/no-witness drivers.

## Feature flags

- `ragu-backend`: enable in-memory R1CS recorder and mock prover.
- `halo2-backend`: reserved host integration flag.
- `ragu-orchard`: Orchard-aligned constants and helpers.
- `ragu-nonuniform`: polynomial oracle and eval drivers (default).

## Wire semantics

- Proving driver: `W = wire index` (usize).
- Verification driver: `W = field element` value.
- Public-input driver: `W = field element` value; `IO` collects outputs.

## Non-uniform evaluation

- `poly::PolynomialOracle<F>` answers add/mul queries; `PolyProverDriver` executes assignment closures; `PolyVerifierDriver` skips them and evaluates linear combinations without heap allocations.

## Split accumulation

- Accumulators are typed states; split accumulators are folded independently per node; recursion emits tupled states; verification remains O(1).
