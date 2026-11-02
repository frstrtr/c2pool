c2wallet-qt-signer: the offline signer
=======================================

This program holds keys and signs. It is built network-incapable: it links
Qt6 Core/Gui/Widgets and no networking library, and every release re-checks
the packaged binary for networking libraries and symbols. Use it on a
machine that stays offline.

Air-gap rules
-------------
- Run it on a machine with networking disabled (no cable, Wi-Fi and
  Bluetooth off), and keep that machine offline afterwards.
- Carry only public data across the gap: unsigned transactions and UTXO
  lists in, signed transactions, manifests and message signatures out.
- Never type a seed or key into an online machine.

Verify the download BEFORE copying it to the offline machine
------------------------------------------------------------
The release has a SHA256SUMS file signed by the maintainer
(SHA256SUMS.asc). On a machine with the maintainer's public key:

    gpg --verify SHA256SUMS.asc SHA256SUMS
    shasum -a 256 -c SHA256SUMS --ignore-missing      (macOS)
    sha256sum -c SHA256SUMS --ignore-missing          (Linux)
    certutil -hashfile <file> SHA256                  (Windows: compare by eye)

The SHA256SUMS check is the trust anchor; the operating-system prompts below
are not. MANIFEST.txt inside the package lists the sha256 of every file in
it, so the program itself can be checked even where the container (DMG,
setup.exe, AppImage) is not bit-reproducible.

Linux
-----
c2wallet-qt-signer-<version>-linux-x86_64.AppImage: chmod +x, then run it.
Without FUSE, run it with --appimage-extract-and-run. The .tar.gz holds the
same files as the AppImage: unpack it and run ./AppRun. Needs glibc 2.39 or
newer (Ubuntu 24.04 or later).

macOS (universal: Apple silicon and Intel; macOS 12 or later)
-----
The app is ad-hoc signed, not notarized. A copy that a browser, AirDrop or
Messages downloaded is quarantined, and Gatekeeper refuses to open it:
  - macOS 14: "cannot be opened because the developer cannot be verified";
    right-click the app, Open, then Open again.
  - macOS 15: "Apple could not verify ... is free of malware"; right-click
    Open no longer helps. Open System Settings -> Privacy & Security and
    press "Open Anyway" once, or run:
        xattr -dr com.apple.quarantine c2wallet-qt-signer.app
A copy made from a FAT or exFAT USB stick carries no quarantine flag (those
file systems store no extended attributes), so Gatekeeper does not engage;
a stick formatted APFS or HFS+ keeps the flag.

Windows (x86_64)
-------
Unsigned: SmartScreen shows "Windows protected your PC". Press "More info",
then "Run anyway". The setup.exe installs per user, needs no administrator
rights and opens no firewall port; the .zip runs from any folder. The
program needs the Microsoft Visual C++ 2015-2022 runtime (x64); setup.exe
installs it when it is missing (that one step asks for administrator rights).

Confirmation words
------------------
SPEND signs a transaction that moves money. SIGN signs a message (no money
moves; a message signature can never be replayed as a transaction).
