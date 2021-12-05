# ghidra-lx-loader

Ghidra Loader for the LX/LE executable file format

## Installation

Download a release matching your ghidra version from the [releases](https://github.com/yetmorecode/ghidra-lx-loader/releases) to the `Extensions/Ghidra` inside your Ghidra installation and enabled it from `File > Install extensions...`.

## Features

* Adds support for LX and LE-style executable formats to Ghidra
* Full fixup support for:
  * 16-bit selector fixups (type 2)
  * 16:16 pointer fixups (type 3)
  * 16/32-bit offset fixups (type 5 & 7)
  * 32-bit self-ref fixups (type 8)
* Unimplemented fixups (not seen anywhere yet):
  * byte fixups (type 0)
  * 16:32 pointer fixups (type 6)
  * Undefined by spec: type 1 & 4 
* Unhandled fixups will be logged
* Loader option to manually override the object base addresses and segment selectors

## Manually overriding base addresses and segment selectors

The loader can be instructed to manually override the base addresses and selectors of the executable's objects. I use this to feed Ghidra the same memory layout and segment selectors as I find in the dosbox debugger. In return I can use the same addresses found in Ghidra to set breakpoints in the debugger etc.

To override the base addresses, just enter a comma-seperated list of hex values into the field:

![Options](data/options.png)

The loader will adjust the locations (and fixups!) accordingly:

![New locations](data/options2.png)

## Resources

* https://ghidra-sre.org/
* https://moddingwiki.shikadi.net/wiki/Linear_Executable_(LX/LE)_Format

## Tested with

* F1 Manager Professional: https://www.mobygames.com/game/dos/f1-manager-professional
* The Elder Scrolls Redguard: https://en.wikipedia.org/wiki/The_Elder_Scrolls_Adventures:_Redguard

## Feedback

If you got any feedback, please don't hesitate to open a ticket. Even if you are just using the loader without any issues I'd be happy to hear about :)