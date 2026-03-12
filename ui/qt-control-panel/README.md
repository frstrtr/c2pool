# c2pool Qt Control Panel (MVP Scaffold)

This is the initial mining-first MVP scaffold for the desktop control panel.

Implemented in this first cut:

- Qt Widgets app shell
- Sidebar navigation
- Overview page
- Mining page
- Logs page
- Basic node/miner monitoring refresh loop
- Log export action (calls /logs/export endpoint)

## Build

```bash
cmake -S ui/qt-control-panel -B build-qt-mvp
cmake --build build-qt-mvp -j4
```

## Run

```bash
./build-qt-mvp/c2pool-qt-control-panel
```

Default API base URL in the app:

- http://127.0.0.1:9332

Use the top bar to change base URL and refresh pages.

## Current status

This is a functional skeleton meant to start MVP implementation quickly.
Data mapping, UI polish, and deeper controls will be implemented incrementally.
