// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include <QCheckBox>
#include <QComboBox>
#include <QDoubleSpinBox>
#include <QGroupBox>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QProcess>
#include <QPushButton>
#include <QSpinBox>
#include <QTableWidget>
#include <QTextEdit>
#include <QWidget>

class SettingsStore;

/// Daemon launch-configuration page.
///
/// Coin-generic (profile-driven — see CoinProfiles.hpp). Supports both
/// c2pool launch CLIs: the unified `c2pool --net …` binary (LTC/BTC/DOGE)
/// and the dedicated per-coin binaries (c2pool-dash / c2pool-dgb /
/// c2pool-bch) whose run-loop uses the reward-SAFE `--coin-rpc` /
/// `--coin-rpc-auth` arm.
///
/// Provides a GUI form covering the important c2pool CLI flags:
///   • Operation mode (integrated / sharechain / solo)
///   • Network (litecoin / bitcoin / dogecoin / dash / digibyte /
///     bitcoincash, testnet toggle)
///   • Binary path + ports (P2P, stratum, HTTP API)
///   • Parent coin-daemon RPC credentials / conf-file path
///   • Payout address, node-owner fee (-f), dev donation (--give-author)
///   • Redistribute mode for invalid-address miners (--redistribute)
///   • Merged-mining chains table (--merged SYMBOL:CHAIN_ID:HOST:PORT:USER:PASS[:P2P])
///   • ★ Advanced / embedded (opt-in, reward-UNSAFE) — default OFF; the
///     only place --coin-p2p-connect / --embedded-mainnet can be emitted
///   • Generated-command preview
///   • Launch / Stop / Restart daemon buttons
///
/// The widget owns its own QProcess so MainWindow toolbar buttons simply
/// delegate to launch() / stop() / restart().
class PageLaunch : public QWidget
{
    Q_OBJECT
public:
    /** SettingsStore is optional — when passed, load/save route
     *  through the active profile's launch group
     *  (profiles/<active>/launch/*); when null, the legacy
     *  top-level [launch] group is used. MainWindow passes one so
     *  connection-profile switches reload the form correctly. */
    explicit PageLaunch(SettingsStore* settings = nullptr, QWidget* parent = nullptr);

    /// Build the full shell command from current form state.
    QString buildCommand() const;
    QString suggestedApiBaseUrl() const;

    /// Persist form state to QSettings under the "launch/" prefix.
    void saveSettings() const;
    /// Restore form state from QSettings.
    void loadSettings();

    /// True when the managed QProcess is running.
    bool isDaemonRunning() const;

public slots:
    void launch();
    void stop();
    void restart();

signals:
    /// Emitted whenever daemon process state changes.
    /// text/style are for the MainWindow status label.
    void daemonStateChanged(const QString& text, const QString& styleSheet);
    void apiBaseUrlChanged(const QString& url);

private slots:
    void onBuildPreview();
    void addMergedRow();
    void removeSelectedMergedRow();
    void updateNetworkDefaults();
    void emitApiBaseUrlChanged();

private:
    void setupUi();
    QGroupBox* makeGroup(const QString& title);
    /// Build the command line for a LegacyUnified coin (`c2pool --net …`).
    QString buildLegacyCommand() const;
    /// Build the command line for a PerCoinRun coin (c2pool-dash/-dgb/-bch,
    /// reward-SAFE dashd-RPC arm; embedded arm only when opted in).
    QString buildPerCoinCommand() const;
    /// Currently-selected chain symbol (chain combo userData/text).
    QString currentChain() const;
    /// Apply profile-driven UI state (daemon-group label, per-coin note,
    /// embedded-group visibility, conf-path enablement) for the current
    /// chain WITHOUT resetting user-edited ports/binary. Called by both
    /// updateNetworkDefaults() (after it snaps ports) and loadSettings().
    void applyProfileUi();
    /** Return the QSettings group prefix the form persists to:
     *  "profiles/<active>/launch" when settings_ is set,
     *  "launch" otherwise. */
    QString launchGroupPath() const;

    SettingsStore* settings_{nullptr};
    QProcess* process_;

    // ── Mode / Network ──────────────────────────────────────────────────────
    QComboBox* modeCombo_;       ///< integrated / sharechain / solo
    QCheckBox* testnetCheck_;
    QComboBox* chainCombo_;      ///< coin-generic (CoinProfiles.hpp order)
    QLabel*    coinNoteLabel_{nullptr};  ///< per-coin note (masternode / experimental / CLI arm)

    // ── Executable ─────────────────────────────────────────────────────────
    QLineEdit* binaryEdit_;

    // ── Ports ───────────────────────────────────────────────────────────────
    QSpinBox*  p2pPortSpin_;
    QSpinBox*  stratumPortSpin_;
    QSpinBox*  httpPortSpin_;

    // ── Parent Coin Daemon ──────────────────────────────────────────────────
    QGroupBox* coindGroup_{nullptr}; ///< relabelled per coin (daemon name)
    QLineEdit* coindHostEdit_;
    QSpinBox*  coindPortSpin_;       ///< 0 = auto-detect from chain
    QLineEdit* rpcUserEdit_;
    QLineEdit* rpcPassEdit_;
    QSpinBox*  coindP2pPortSpin_;    ///< --coind-p2p-port
    QLineEdit* coindP2pAddrEdit_;    ///< --coind-p2p-address
    // PerCoinRun creds file: rpcpassword is read from the coin .conf and
    // NEVER placed on argv. Blank ⇒ the binary's default conf path.
    QLineEdit* rpcConfPathEdit_{nullptr}; ///< --coin-rpc-auth / --rpc-conf PATH
    QLineEdit* dataDirEdit_{nullptr};     ///< --data-dir PATH (per-instance state root)

    // ── Payout & Fees ───────────────────────────────────────────────────────
    QLineEdit*     addressEdit_;
    QCheckBox*     autoDetectWalletCheck_; ///< --auto-detect-wallet (default on)
    QDoubleSpinBox* feeSpinBox_;        ///< -f / --fee (node-owner fee %)
    QDoubleSpinBox* giveAuthorSpinBox_; ///< --give-author (dev donation %)
    QLineEdit*     nodeOwnerAddrEdit_;
    QLineEdit*     nodeOwnerScriptEdit_; ///< --node-owner-script (hex)
    QComboBox*     redistributeCombo_;  ///< pplns / fee / boost / donate

    // ── Merged Mining ───────────────────────────────────────────────────────
    /// Columns: Symbol | Chain ID | Host | Port | User | Password | P2P Port
    QTableWidget* mergedTable_;
    QPushButton*  addMergedBtn_;
    QPushButton*  removeMergedBtn_;

    // ── Network Tuning ────────────────────────────────────────────────────
    QSpinBox*  maxConnsSpinBox_;   ///< --max-conns
    QPlainTextEdit* seedNodesEdit_;  ///< -n HOST:PORT (one per line)
    QLineEdit* httpHostEdit_;        ///< --http-host (bind address)

    // ── Private Sharechain ───────────────────────────────────────────────────
    QCheckBox*   privateChainCheck_;   ///< Enable private sharechain
    QLineEdit*   networkIdEdit_;       ///< --network-id (hex)
    QPushButton* generateIdBtn_;       ///< Generate random network ID
    QLabel*      privateStatusLabel_;  ///< "Public network" / "Private chain"
    QComboBox*   startupModeCombo_;   ///< auto / genesis / wait

    // ── Advanced ────────────────────────────────────────────────────────────
    QLineEdit* configFileEdit_;      ///< --config (YAML file)
    QLineEdit* messageBlobEdit_;     ///< --message-blob-hex
    QLineEdit* coinbaseTextEdit_;    ///< --coinbase-text

    // ── ★ Advanced / embedded (opt-in, REWARD-UNSAFE) ────────────────────────
    // Default OFF. This is the ONLY place --coin-p2p-connect /
    // --embedded-mainnet may be emitted. Guarded per the DASH hotel
    // incident: an unguarded embedded arm produced reward-unsafe blocks.
    QGroupBox*      embeddedGroup_{nullptr};
    QCheckBox*      embeddedP2pCheck_{nullptr};   ///< enables --coin-p2p-connect (default OFF)
    QPlainTextEdit* embeddedP2pPeersEdit_{nullptr}; ///< HOST:PORT per line
    QCheckBox*      embeddedMainnetCheck_{nullptr}; ///< enables --embedded-mainnet (default OFF, DASH)
    QLabel*         embeddedWarnLabel_{nullptr};

    // ── Command Preview ─────────────────────────────────────────────────────
    QTextEdit*   cmdPreview_;
    QPushButton* buildPreviewBtn_;
    QPushButton* launchBtn_;
    QPushButton* stopBtn_;
    QPushButton* restartBtn_;
};