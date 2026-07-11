# flux-cross-assembler


## Meta

**Domain:** constraint-theory
**Depends on:** —
**Depended by:** —
**Implements:** Dual-target FLUX assembler — cloud (4-byte fixed) and edge (variable-width) byte...
**Related:** flux-runtime, nexus-edge-runtime, isa-v3-edge-spec


Dual-target FLUX assembler — compiles `.fluxasm` source to either cloud (4-byte fixed) or edge (variable-width) bytecode.

Built from the ISA v3 dual-mode spec co-designed by Oracle1 (cloud encoding) and JetsonClaw1 (edge encoding).

## Usage

```bash
# Assemble for cloud (flux-runtime Python/C)
python3 cross_asm.py --target cloud program.fluxasm -o program.fbc

# Assemble for edge (Jetson Orin Nano)
python3 cross_asm.py --target edge program.fluxasm -o program.fbc

# Disassemble (auto-detect target)
python3 cross_asm.py --target cloud --disassemble program.fbc

# Run tests
python3 cross_asm.py --test
```

## Architecture

- **Frontend:** Shared parser for `.fluxasm` syntax (labels, comments, operands)
- **Backend:** Cloud (4-byte fixed) or Edge (variable-width 1-3 byte)
- **Opcode mapping:** Semantic mnemonics → target-specific byte sequences
- **Confidence fusion:** `CADD`/`CSUB`/`CMUL`/`CDIV` work on both targets
- **Density:** Edge encoding is ~69% the size of cloud for equivalent programs

## Spec Compliance

- **Cloud:** ISA v2 ([flux-runtime opcodes.py](https://github.com/SuperInstance/flux-runtime))
- **Edge:** ISA v3 ([isa-v3-edge-spec](https://github.com/Lucineer/isa-v3-edge-spec))

## Example

Same source compiles to both targets:

```asm
MOVI R1, 3
MOVI R2, 4
IADD R0, R1, R2
HALT
```

**Cloud output:** `2b0103002b0204000800010280000000` (16 bytes)
**Edge output:** `ca010300ca020400840020` (11 bytes, 31% smaller)

## Test Results

```
12/12 tests passing
✅ Cloud NOP, MOVI, IADD, multi-instruction programs
✅ Edge NOP, HALT, CADD, LDI, density comparison
✅ Cloud + Edge disassembly round-trip
✅ Density: edge=11B cloud=16B (68.8%)
```

## Co-Design

This assembler is the bridge between Oracle1's cloud ISA and JetsonClaw1's edge ISA. Both agents independently designed their encodings, then converged through the bottle protocol:
- Oracle1: CAPABILITY.toml, A2A adapter, WASM target, conformance fix (88/88)
- JetsonClaw1: ISA v3 edge spec, conformance runner, tri-language modules

The cross-assembler makes one source file produce correct bytecode for either target — the agent writes code once, the assembler handles the translation.

## Related Repos

- **[flux-runtime](https://github.com/SuperInstance/flux-runtime)** — cloud runtime whose ISA v2 opcodes define this assembler's 4-byte cloud target; the direct consumer of cloud bytecode output.
- **[isa-v3-edge-spec](https://github.com/Lucineer/isa-v3-edge-spec)** — defines the variable-width edge encoding that this assembler's edge target implements.
- **[nexus-edge-runtime](https://github.com/SuperInstance/nexus-edge-runtime)** — contains a bytecode VM and wire protocol for edge execution; shares the edge-bytecode problem domain.
