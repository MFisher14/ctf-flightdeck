"""Plugins: a platform flightdeck does not know, played through a program of the player's own.

A plugin is a folder with a plugin.toml (manifest.py) and a program flightdeck runs once per
call, out of process, with one JSON object on stdin and one on stdout (call.py): `pull`,
`submit`, `solved`. Nothing of a plugin is ever imported. Only the player's config allows one
(`[plugins.NAME] path`, written by `flightdeck plugin add` after it showed what the plugin
runs and gets); an event profile only selects it by name. flightdeck writes what a pull lists
into the board folder itself and reads it back as any untrusted board (board.py).

A plugin is not sandboxed: it runs as the player. It is given the event's URL, the event's
token and an environment without the player's other keys (call.child_env). flightdeck never
downloads, installs or updates one.
"""
