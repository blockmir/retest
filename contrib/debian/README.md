
Debian
====================
This directory contains files used to package donated/donate-qt
for Debian-based Linux systems. If you compile donated/donate-qt yourself, there are some useful files here.

## donate: URI support ##


donate-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install donate-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your donateqt binary to `/usr/bin`
and the `../../share/pixmaps/donate128.png` to `/usr/share/pixmaps`

donate-qt.protocol (KDE)

