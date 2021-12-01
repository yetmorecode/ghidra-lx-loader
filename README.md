# ghidra-lx-loader

Ghidra Loader for the LX/LE executable file format

## Installation

Download a release matching your ghidra version from the [releases](https://github.com/yetmorecode/ghidra-lx-loader/releases) to the `Extensions/Ghidra` inside your Ghidra installation and enabled it from `File > Install extensions...`.

## Features

* Adds support for LX and LE-style executable formats to Ghidra
* Full support for 32 bit offset fixups (also across page boundaries)
* Unhandled fixups will be logged (if any)
* Loader option to manually override the object base addresses

## Manually overriding base addresses

The loader can be instructed to manually override the base addresses of the executable's objects. I use this to feed Ghidra the same memory layout I find in the dosbox debugger. In return I can use the same addresses found in Ghidra to set breakpoints in the debugger etc.

To override the base addresses, just enter a comma-seperated list of hex values into the field:

![Options](data/options.png)

The loader will adjust the locations (and fixups!) accordingly:

![New locations](data/options2.png)

## Resources

* https://ghidra-sre.org/
* https://moddingwiki.shikadi.net/wiki/Linear_Executable_(LX/LE)_Format
