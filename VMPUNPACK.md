# The `vmpunpack` branch

This is a **modified fork** of [momo5502/sogen](https://github.com/momo5502/sogen). This branch adds
the emulator-side half of [vmpunpack](https://github.com/milk-analyzer/vmpunpack), a generic unpacker
for VMProtect-packed x64 PE malware.

It exists so that the patched `analyzer.exe` vmpunpack uses is distributed **with its corresponding
source**, as GPL-2.0 §3 requires. Everything here is GPL-2.0, same as upstream.

## What is changed

Branched from upstream **`e3a416b`**, five commits, **8 files, +406 / −10**.

| commit | topic | why |
|---|---|---|
| 1 | `analyzer`: delay-load `whp-emulator.dll` | Without it `analyzer.exe` fails to start on a Windows 10 host that has no Hyper-V, before `main()` runs. |
| 2 | `sleigh`: `SBB r64,imm32` sign-extension, `XCHG m32,r32` zero-extension | Two x86-64 decode defects in the SLEIGH data the icicle backend compiles at runtime. VMProtect's integrity arithmetic depends on the hardware behaviour, so the emulated result diverged. |
| 3 | `exceptions`: dispatch `NtRaiseException(FirstChance=TRUE)` | Upstream logs "not supported" and aborts. Protected binaries route real control flow through SEH/VEH, so the run ended at the first raise. |
| 4 | `emulator`: `SOGEN_NODELAY`, `SOGEN_TSC_STRIDE` | Collapse anti-sandbox sleeps and rdtsc delay loops. |
| 5 | `emulator`: `SOGEN_UNPACK` — stop at OEP and dump the image | The core: arm an execution hook on the target's original code section, and on first hit dump the fully unpacked image plus its metadata. |

Commits 2 through 5 are independent of each other; 1 is a host-compatibility fix that only affects
startup.

## Environment variables

All are read from the environment and **default to off**. Without `SOGEN_UNPACK` the emulator behaves
exactly as upstream.

| variable | effect |
|---|---|
| `SOGEN_UNPACK` | arm the OEP hook and dump the unpacked image |
| `SOGEN_STOP_AT_OEP` | stop at the OEP instead of continuing past it |
| `SOGEN_OEP_RVA` | force the OEP RVA, overriding the section heuristic |
| `SOGEN_LATEDUMP_AT` | additionally dump image and heap N basic blocks after the OEP |
| `SOGEN_NODELAY` | satisfy `NtDelayExecution` immediately |
| `SOGEN_TSC_STRIDE` | advance the emulated TSC by a fixed stride per `rdtsc`/`rdtscp` |
| `SOGEN_TRAIL`, `SOGEN_PROFILE` | diagnostic only: basic-block ring buffer, register probes, block profile |

## Output contract

With `SOGEN_UNPACK=1`, on reaching the OEP:

| file | contents |
|---|---|
| `C:\dumps\unpacked.bin` | the image, `[base, base + SizeOfImage)` |
| `C:\dumps\unpacked.meta` | `base=0x…`, `size_of_image=0x…`, `entry_rva=0x…`, `oep_rva=0x…` |
| `C:\dumps\unpacked_late.bin`, `C:\dumps\heap.bin` | with `SOGEN_LATEDUMP_AT` |
| `C:\dumps\sogen_image.bin` | diagnostic one-shot dump on an unmapped fault |

## Building

Standard sogen MSVC build; see `.github/workflows/vmpunpack-release.yml` for the exact recipe.

```bat
cmake --preset=release
cmake --build --preset=release
```

Artifacts land in `build/release/artifacts/`. The `.sinc` files from commit 2 are data compiled by
icicle at load time, so they take effect without a rebuild of the backend.

## Notes for a possible upstream PR

Two things here are deliberately *not* upstream-ready, and are kept as-is because vmpunpack depends on
this exact behaviour:

1. **The dump paths are hardcoded under `C:\dumps`.** The vmpunpack wrapper owns and clears that
   directory per run. Upstream would want these routed through a config option or a callback.
2. **The `[DIAG]` / `[PROFILE]` scaffolding** in `windows_emulator.cpp` is left in. It is
   development aid from the original reversing effort, gated behind its own env vars and off by
   default, but it is noise in a feature branch.

Commits 1, 2 and 3 are independently useful and would stand on their own upstream.
