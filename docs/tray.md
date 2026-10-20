# Tray app

`savesctl tray` starts a system tray icon that mirrors the daemon.

## Menu

- Status line (read only): Up to date, Syncing N, Paused, N conflicts,
  Daemon stopped or Server unreachable.
- Sync now: syncs all tracked games.
- Pause all / Resume all toggles syncing.
- Games: per game a submenu with Sync now, Pause or Resume, Open save
  folder, and the last error when one exists.
- Conflicts: one entry per pending conflict with Keep local, Keep remote
  and Keep newest choices.
- Open logs, Open config folder, Start at login, Start or Stop daemon,
  Quit tray.

The icon reflects the aggregate state: ok, syncing, paused, conflict,
error or offline.

## Files

The tray stores a single instance lock and the daemon endpoint under the
state dir runtime subdir.

## Autostart

`savesctl tray install` and `savesctl daemon install` write user level
startup entries (systemd user unit and XDG autostart on Linux, HKCU Run
values on Windows). `daemon uninstall` and `tray uninstall` remove them.

## Desktop notes

KDE and XFCE support tray icons natively. GNOME needs the AppIndicator
shell extension for the icon to appear. Wayland sessions work the same
through D-Bus.

On Windows the tray runs without a console window and uses the Run
registry key for autostart.
