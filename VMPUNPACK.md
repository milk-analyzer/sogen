# The `vmpunpack` branch

This is a **modified fork** of [momo5502/sogen](https://github.com/momo5502/sogen). This branch adds
the emulator-side half of [vmpunpack](https://github.com/milk-analyzer/vmpunpack), a generic unpacker
for VMProtect-packed x64 PE malware.

It exists so that the patched `analyzer.exe` vmpunpack uses is distributed **with its corresponding
source**, as GPL-2.0 §3 requires. Everything here is GPL-2.0, same as upstream.

## What is changed

Branched from upstream **`e3a416b`**. The six topics below carry the feature; other commits fix
defects found reviewing them and add the release build.

| commit | topic | why |
|---|---|---|
| 1 | `analyzer`: delay-load `whp-emulator.dll` | Without it `analyzer.exe` fails to start on a Windows 10 host that has no Hyper-V, before `main()` runs. |
| 2 | `sleigh`: `SBB r64/m64,imm32` sign-extension, `XCHG m32,r32` zero-extension | Two x86-64 decode defects in the SLEIGH data. **Affects the icicle backend only** — SLEIGH is not used by unicorn, which is what vmpunpack runs, so this matters for icicle users and for upstream, not for the unpack path here. |
| 3 | `exceptions`: dispatch `NtRaiseException(FirstChance=TRUE)` | Upstream logs "not supported" and aborts. Protected binaries route real control flow through SEH/VEH, so the run ended at the first raise. |
| 4 | `emulator`: `SOGEN_NODELAY`, `SOGEN_TSC_STRIDE` | Collapse anti-sandbox sleeps and rdtsc delay loops. |
| 5 | `emulator`: `SOGEN_UNPACK` — stop at OEP and dump the image | The core: arm an execution hook on the target's original code section, and on first hit dump the fully unpacked image plus its metadata. |
| 6 | `emulator`: host containment, `SOGEN_ALLOW_NETWORK` | Upstream forwards guest sockets and DNS to the host's network stack, guest windows and audio to the host desktop, and two paravirtual devices to the host's Vulkan driver and Steam client. This build is pointed at live malware, so all of that is closed. See [Host containment](#host-containment). |

Topics 2 through 6 are independent of each other; 1 is a host-compatibility fix that only affects
startup.

## Environment variables

All are read from the environment and **default to off**. Without `SOGEN_UNPACK` the emulator behaves
as upstream, except for [host containment](#host-containment), which applies to every run of this build.

| variable | effect |
|---|---|
| `SOGEN_UNPACK` | arm the OEP hook and dump the unpacked image |
| `SOGEN_STOP_AT_OEP` | stop at the OEP instead of continuing past it |
| `SOGEN_OEP_RVA` | force the OEP RVA, overriding the section heuristic |
| `SOGEN_LATEDUMP_AT` | additionally dump image and heap N basic blocks after the OEP |
| `SOGEN_NODELAY` | satisfy `NtDelayExecution` immediately |
| `SOGEN_TSC_STRIDE` | advance the emulated TSC by a fixed stride per `rdtsc`/`rdtscp` |
| `SOGEN_ALLOW_NETWORK` | `1` forwards guest sockets and DNS to the host's network, as upstream does. Any other value, `0` and `true` included, leaves the network blocked. |
| `SOGEN_TRAIL`, `SOGEN_PROFILE` | diagnostic only: basic-block ring buffer and block profile |

> `SOGEN_DIAG` gates the remaining `[DIAG]` scaffolding: the access-violation register/instruction dump
> and eight probe hooks whose addresses are one sample's handler offsets. `SOGEN_TRAIL` implies it,
> because the AV block is the only reader of the ring buffer. The one-shot `sogen_image.bin` write is
> gone — it duplicated `unpacked.bin` from two hardcoded literals and nothing read it.

## Host containment

Applies to every run, with or without `SOGEN_UNPACK`.

| upstream | this build |
|---|---|
| A guest socket is a host socket: `connect`, `sendto`, `bind`, `listen` and `accept` act on the host's interfaces, loopback included. | `offline_socket_factory`: sockets are created, bound and put into the listening state, and nothing connects, arrives or leaves. No socket is created on the host; `WSAStartup` still runs. See the table below for what each call returns. |
| A guest DNS query is the host's `getaddrinfo`. | `localhost` resolves to `127.0.0.1` / `::1`. Every other name fails to resolve, the emulated machine's own name included. |
| Guest windows are host windows (SDL), host keyboard and mouse input reaches the guest, guest audio plays on the host. | `null_ui_backend` and `null_audio_backend`. The Emscripten build keeps upstream's web backends. |
| `\\.\SogenGpu` loads the host's Vulkan loader and submits guest work to the host GPU. | The name opens and every ioctl fails with `STATUS_NOT_SUPPORTED`. The Vulkan host is not linked into `analyzer.exe`. |
| `\\.\SogenSteam` loads the host's `steamclient64.dll` and proxies Steamworks calls, HTTP and networking included, under the logged-in account. | The name opens and every ioctl fails with `STATUS_NOT_SUPPORTED`. `SOGEN_ENABLE_STEAM` defaults to `OFF` on this branch, so the host backend is not built. |

`SOGEN_ALLOW_NETWORK=1` restores the first two rows and nothing else. It is read once per process. A
frontend that passes its own `emulator_interfaces` — the test and fuzz harnesses do — keeps what it
passed, and the startup line below then describes the default, not what was passed.

What a guest socket call returns with the network blocked:

| call | stream socket | datagram socket |
|---|---|---|
| `bind` | succeeds; port 0 is replaced by one from 49152–65535 | same |
| `listen` | succeeds; `accept` never completes | — |
| `connect` to 127.0.0.0/8, `::1`, `::ffff:127.x.x.x` | `STATUS_CONNECTION_REFUSED` → `WSAECONNREFUSED` | succeeds, records the peer |
| `connect` to any other address | `STATUS_NETWORK_UNREACHABLE` → `WSAENETUNREACH` | succeeds, records the peer |
| `send` / `sendto` to a loopback address | not connected | accepted and dropped |
| `send` / `sendto` to any other address | not connected | `STATUS_NETWORK_UNREACHABLE` → `WSAENETUNREACH` |
| `recv` / `recvfrom` | not connected | never completes |
| poll | never ready | writable, never readable |

The failures are synchronous, for non-blocking sockets too: a failed `connect` is returned by the call
and is not signalled later through `select` or `FD_CONNECT`. Traffic between two guest sockets is not
carried, so a sample that talks to itself over loopback sees a closed port.

With `SOGEN_UNPACK` set, or with the network allowed, the mode is printed once at startup. It is the
first thing the emulator's constructor does, before any guest code runs:

```
[UNPACK] host network: blocked
[UNPACK] host network: LIVE (SOGEN_ALLOW_NETWORK=1) - guest sockets and DNS use the real network
```

Guest code can print arbitrary lines later in the run, so only the first occurrence means anything.

The peer of every `connect` and `sendto` is reported through `on_generic_activity` as
`Network connect: <ip>:<port>` / `Network sendto: <ip>:<port>`, whether or not the network is allowed.
An endpoint does not repeat the peer it reported last; alternating between two peers reports each
change. DNS names were already reported as `DNS query: <name>`. Both reach `--report`.

With the null UI backend a guest dialog is not shown and cannot be dismissed. A protector that opens a
message box before the OEP waits in its message loop until the caller's timeout, as it did when the SDL
window was shown and nobody clicked it; the text of the box is not printed.

Not covered:

- The guest sees the host's wall clock unless `--reproducible` is passed, and the timestamps and file
  ids of files in the emulation root are the host's.
- Guest file writes stay inside the emulation root and persist there across runs.
- The Linux frontend (`EMULATOR_LINUX=1`, linked into the same `analyzer.exe`) has socket syscalls of its
  own that do not consult `SOGEN_ALLOW_NETWORK`. On a Windows host they are compiled out and return
  `ECONNREFUSED`; on any other host they open host sockets. Only the Windows build is released, and
  vmpunpack removes `EMULATOR_*` from the engine's environment.

`.github/vmpunpack-nettest.py` checks the first row of the table above against a built `analyzer.exe`: a
benign guest, Microsoft's `finger.exe`, must reach a listener on the host's loopback with
`SOGEN_ALLOW_NETWORK=1` and must not without it. The release workflow runs it on the packaged files.
The `analyzer-test` CTest sets `SOGEN_ALLOW_NETWORK=1`, because upstream's test sample resolves a public
name and round-trips a loopback datagram through the host.

## Output contract

With `SOGEN_UNPACK=1`, on reaching the OEP:

| file | contents |
|---|---|
| `C:\dumps\unpacked.bin` | the image, `[base, base + SizeOfImage)` |
| `C:\dumps\unpacked.meta` | `base=0x…`, `size_of_image=0x…`, `entry_rva=0x…`, `oep_rva=0x…` |
| `C:\dumps\unpacked_late.bin`, `C:\dumps\heap.bin` | with `SOGEN_LATEDUMP_AT` |

If the image cannot be written in full, the partial file is removed and **`unpacked.meta` is
deliberately not written**. An integrator seeing a missing meta after an OEP hit should read that as a
failed dump, not a crash; the reason is on stdout.

## Building

Standard sogen MSVC build; see `.github/workflows/vmpunpack-release.yml` for the exact recipe.

```bat
cmake --preset=release
cmake --build --preset=release
```

`SOGEN_ENABLE_STEAM` defaults to `OFF` here, so the configure step does not need the `libclang` pip
package and fetches nothing from Valve's Proton repository. A build directory configured before that change
keeps `ON` in its cache; pass `-DSOGEN_ENABLE_STEAM=OFF` once.

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
