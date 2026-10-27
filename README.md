# Cricket07FreeHit

An ASI plugin that extends EA Sports Cricket 07's existing free-hit rule to limited-overs matches.

## Features

- Free hits in international, domestic and exhibition limited-overs matches, including custom match lengths.
- Supports modified executables when the required game routines are compatible.
- Logs compatibility warnings and skips the patch if required checks fail.

## Installation

1. Close Cricket 07.
2. Ensure the **32-bit [Ultimate ASI Loader](https://github.com/ThirteenAG/Ultimate-ASI-Loader)** is installed. Keep your existing loader if it already works with other ASI plugins.
3. Copy `Cricket07FreeHit.asi` into the game folder, beside `Cricket07.exe`.
4. Launch the game and check `Cricket07FreeHit.log` for `APPLIED`.

Keep only one copy of the plugin. To uninstall, close the game and remove `Cricket07FreeHit.asi`.

## Troubleshooting

| Problem | What to check |
|---|---|
| No log file | Confirm the ASI is beside the executable, the folder is writable, and your loader supports `InitializeASI`. |
| SHA-256 warning | A modified executable was detected. This warning alone does not disable the plugin; look for `APPLIED` afterward. |
| `WARNING: NOT APPLIED` | The log identifies an incompatible routine, layout or conflicting hook. Use a compatible executable and check for overlapping plugins. |
| No free hit | Confirm `APPLIED`, restart the game, and test a played limited-overs match after a no-ball. Instant simulation is not verified. |

The plugin retains the game's existing no-ball triggers and free-hit behavior.
