TODO
====

## General
- [ ] Use Struct.pack()
- [ ] Check parameters for right type

## export.py
### Savegame
- [ ] extract_banner()
- [ ] extract_icon()
- [ ] self.savegameId -> uint64?

## formats.py
### NetConfig
- [X] set_key()
- [ ] set_key(): Interpret HEX as ASCII if length of ASCII
- [X] set_encryption()
- [X] set_proxy() (also for proxyCopy)
- [X] set_mtu()

### IplSave
- [ ] add_title()
- [ ] delete_title()
- [ ] delete_position()
- [X] add_disc_channel()