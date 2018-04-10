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

## export.py
### locDat
* Corrected a few mistakes
* Fixed a critical bug where set_titles wouldn't work, because the MD5 has to be replaced by the MD5 blanker before hash calculation - this means that modifying the loc.dat now actually works!
* Improved error handling

### Savegame
* Check MD5
* Use right IV at file offset 0x050 - decryption now actually works!
* Raise exception if folder "extraction" fails
* Corrected header for SavegameBanner