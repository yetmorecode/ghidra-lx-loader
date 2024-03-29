# Ultimate Ghidra Loader for the LX/LE executable file format

Download a zip matching your Ghidra version from [releases](https://github.com/yetmorecode/ghidra-lx-loader/releases) and install it from `File > Install extensions...`

## Features

* Supports LE/LX files in various formats:
  * OS/2 LX-Style
  * MSDOS DOS/16 LE-Style
  * MSDOS DOS/4 LE-Style
  * DOS32A sb.exe unbound LE/LX-Style
  * Windows Virtual Device Driver (VxD)
* Full page-map and fixup (relocation) support
* Completely typed executable headers (and other image data) with comments

Optionally, various options can be specified individually for each file:

* Manually override the object base addresses and segment selectors (good for syncing with a debugger / DOSBox)
* Map various image data to an overlay:
  * Map MZ Header
  * Map LX Header
  * Map LX Loader Section
  * Map LX Fixup Section (fully typed!)
  * Map LX Data Section (i.e. the unmodified page data)
* Create labels for each fixup in memory
* Create labels for each page beginning in memory
* Log fixup statistics / Log individual fixup types

## Tested with

* F1 Manager Professional (F1.exe - DOS/4GW LE): https://www.mobygames.com/game/dos/f1-manager-professional
* The Elder Scrolls Redguard (RGFX.exe - DOS/4GW LE): https://en.wikipedia.org/wiki/The_Elder_Scrolls_Adventures:_Redguard
* X-Com: Apocalypse (UFO2P.EXE - DOS/16 LE and unbound LE-style)
* Various files compiled with Open Watcom (DOS32A LE)
* Random VxD files

## Extra

![Options](data/options.png)

![Options](data/imagedata.png)

![Options](data/labels.png)

## Manually overriding base addresses and segment selectors

The loader can be instructed to manually override the base addresses and selectors of the executable's objects. I use this to feed Ghidra the same memory layout and segment selectors as I find in the dosbox debugger. In return I can use the same addresses found in Ghidra to set breakpoints in the debugger etc.

To override the base addresses, just enter a comma-seperated list of hex values into the field:

The loader will adjust the locations (and fixups!) accordingly:

![New locations](data/options2.png)

## Resources

* https://ghidra-sre.org/
* https://moddingwiki.shikadi.net/wiki/Linear_Executable_(LX/LE)_Format
* https://github.com/yetmorecode/dos32a/blob/master/src/dos32a/loader.asm
* https://github.com/open-watcom/open-watcom-v2/blob/master/bld/watcom/h/exeflat.h


## Feedback

If you got any feedback, please don't hesitate to open a ticket. Even if you are just using the loader without any issues I'd be happy to hear about :)
