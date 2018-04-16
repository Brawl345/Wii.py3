Changes in Wii.py3
==================
This file lists all changes that were made from Wii.py to Wii.py3.

## General
* Ported Python 2 code to Python 3
* Corrected Python 2 -> Python 3 behaviour (like `@classmethod` and `bytes` objects)
* Switched class names to CamelCase
* Switched function names to under_score
* Corrected indentation (tabs -> spaces)
* Improved output of `__str__` and added `__repr__`
* Added LICENSE (GPL according to [WiiBrew](http://wiibrew.org/wiki/Wii.py))
* Added docstrings

## Struct.py
* Reformat according to PEP guidelines (and things like `if x == None` -> `if not x`)

## archive.py
### VFF
* **NEW!** Original code by [marcan](https://mrcn.st/t/vffdump.py).

## export.py
### locDat
* Corrected a few mistakes
* Fixed a critical bug where set_titles wouldn't work, because the MD5 has to be replaced by the MD5 blanker before hash calculation - this means that modifying the loc.dat now actually works!
* Improved error handling
* Begin counting slots at 1 rather than 0

### Savegame
* Check MD5
* Use right IV at file offset 0x050 - decryption now actually works!
* Raise exception if folder "extraction" fails
* Corrected header for SavegameBanner

## formats.py
### netConfig
* Rewrote with `ConfigHeader` and `ConfigEntry` classes
* Improved nearly everything
* Use string representation of binaries - it's a bit easier to understand and I'm having a hard time with bitwise operations
* Begin counting slots at 1 rather than 0
* Renamed "config" parameters to "slot" so it's not so confusing
* WEP encryption is now supported (reading + writing)
* Added more functions for manipulating data
* Proxy support (reading + writing)

### iplsave
* Support both "versions" of the file - one is 832 bytes, the new one for >= 4.0 is 1216 bytes
* Divided into `IplSaveHeader` and `IplSaveEntry`
* Unpack values (why have classes if we don't use them!)
* Check MD5 of file
* Added `sort_by_tid()` function
* Removed "movable" flag because it leads to bricks (was never tested in Wii.py)
