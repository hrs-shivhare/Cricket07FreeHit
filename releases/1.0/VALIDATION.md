# Cricket07FreeHit 1.0 validation

Date: 27 October 2026. Target: `E:\Cricket07\Cricket07.exe`.

Reference executable SHA-256: `d776dba0cc506b968f7d228e036cf42aeb4abe45a8d1ad0d7226cdebf91553a2`.

## Recovered native behavior

- REA/Ghidra evidence `ev_428a3fe3571d2937c395863d8c4c436ee54ba906e85e7e4a59793415840abc0e`: activation routine `0x5956A0`, whitelist `{14,15,16,19,20}`, pending field `match+0x21260`, no-ball/wide bits at `match+0x21218`, active field `manager+0xFC`, caller `0x5710C0`.
- `ev_a5f6944a157ff138afeee78a6d98689c48a46bbb8474d71777622469cd020381`: native tournament getter `0x487EB0`.
- `ev_205b1c6c53ca5e263bafd5895228fa2fa2592c4e80dc4fef28b8e14b058ddbbc`: shared no-ball handler `0x5D2AE0` arms pending state.
- `ev_e47c343524210b644df259f9c579b11159f5c4d7c1d404ba1520ff8afa0ac306`: bowled/stumped guards in `0x5D55B0`.
- `ev_ad83b85df1ddc6e6ed4ea9272bf842d9219b9c6089346a1993c612ef43f3409f`: LBW guard in `0x552960`.
- `ev_01061fc3196197a0e3692af6c39f38af07dbf72b8358391ffcf741505c6b41d5`: caught guards in `0x5D1100`.

The new eligibility condition reads the existing signed 16-bit over limit at `match+0x58C4`. It replaces the whitelist and rejoins the original shared body; it does not reproduce or alter the shared body in C.

## Build and native execution results

Built with Zig 0.15.2, `-target x86-windows-gnu -std=c11 -O2 -Wall -Wextra -Werror`.

```text
Native whitelist oracle passed. Checking required routines and malformed images...
Executing patched x86 routine across formats, tournaments, pending states and all delivery flags...
221184 native activation cases, 1108219 checks, 385 warning-path observations, 0 failures.
```

The tests execute the actual x86 activation instructions mapped from the executable into a private allocation. They do not launch the game or write to its executable.

Covered:

- Original native eligibility for tournament IDs 0 through 40.
- Patched routine: over limits `-32768,-2,-1,0,1,5,10,20,40,45,50,32767`; pending values `0,1,255`; all 256 current-delivery flag values; initial active values `0,1,127`; tournament IDs `0,1,14,15,16,19,20,39`.
- Correct active-state output and pending-state consumption, unchanged delivery flags, adjacent manager bytes and tournament identity.
- No image byte changed outside the intended 50-byte block; native code-page protection restored.
- Unrelated executable code mutation accepted; every byte of every frozen required signature individually corrupted and rejected before any patch writes.
- Getter corruptions, duplicate patch installation, wrong architecture, truncated declared image, non-executable code section, an actual non-executable mapped code page, null image and inaccessible match storage safely rejected.
- A larger declared image accepted when required ranges/signatures remain valid.
- Private mapping at a different loaded base, with relocated getter address.
- Compiled ASI loads in a 32-bit Windows process and exports undecorated `InitializeASI` and `GetFreeHitStatus`; `DllMain` does not initialize; repeated initialization is harmless.
- Initializing in the unrelated test host emits the modified-hash warning and rejects its incompatible layout. Log capture: `tests/bin/loader-rejection.log`.
- Executable file SHA-256 unchanged before/after build and tests.

ASI SHA-256: `98957a27b5bf5abf219dc04d57bd930e7543d6bb6c2efab59608d13edb109a52`.

## Practical limits

No live match or live dismissal test was performed. The tests establish instruction-level activation behavior and compatibility rejection, not every gameplay or other-mod interaction.

The native rule is broader than the localized foot-fault description because other no-ball paths can arm its shared handler. Native wide continuation requires a separate end-to-end gameplay test; this plugin deliberately retains that behavior. Practice/special modes with a positive retained over limit are not separately excluded. Instant simulation coverage is not established.

Suggested in-game checks: international/exhibition limited-overs no-ball followed by bowled, caught, LBW, stumped and run-out outcomes; another no-ball or wide; over transition; innings reset; Test-match negative control. These remain unperformed.
