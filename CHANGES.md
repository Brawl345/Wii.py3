Changes in Wii.py3
==================
This file lists all changes that were made from Wii.py to Wii.py3.

## General
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
* Fixed a critical bug where set_titles wouldn't work, because the MD5 has to be replaced by the MD5 blanker before hash calculation - this means that reordering now actually works!
* Improved error handling