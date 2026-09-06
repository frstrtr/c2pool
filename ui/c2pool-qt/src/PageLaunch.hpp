// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include "LaunchCommand.hpp"   // c2pool_qt::PerCoinParams (marshal target)

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
/// c2pool-bch). DASH runs DAEMONLESS by default (bare `--run`); the dashd
/// `--coin-rpc` / `--coin-rpc-auth` arm is an explicit opt-in ("Attach
/// external dashd").
///
/// Provides a GUI form covering the important c2pool CLI flags:
///   • Operation mode (integrated / sharechain / solo / custodial / standalone)
///   • Network (litecoin / bitcoin / dogecoin / dash / digibyte /
///     bitcoincash, testnet toggle)
///   • Binary path + ports (P2P, stratum, HTTP API)
///   • Parent coin-daemon RPC credentials / conf-file path (DASH: opt-in)
///   • Payout address, node-owner fee (-f), dev donation (--give-author)
///   • Redistribute mode for invalid-address miners (--redistribute)
///   • Merged-mining chains table (--merged SYMBOL:CHAIN_ID:HOST:PORT:USER:PASS[:P2P])
///   • Advanced / embedded coin-network (transport + gate-lift) — opt-in;
///     the only place --coin-p2p-connect / --embedded-mainnet can be emitted
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
    /// Re-check the payout / node-owner address fields against the active
    /// coin and refresh the inline status label. Advisory except for a
    /// positively-identified wrong-coin address, which launch() blocks.
    void validateAddressField();

private:
    void setupUi();
    QGroupBox* makeGroup(const QString& title);
    /// Build the command line for a LegacyUnified coin (`c2pool --net …`).
    QString buildLegacyCommand() const;
    /// Build the command line for a PerCoinRun coin (c2pool-dash/-dgb/-bch).
    /// DASH default is bare `--run` (daemonless); the dashd-RPC arm and the
    /// embedded transport knobs are emitted only when their opt-ins are on.
    QString buildPerCoinCommand() const;
    /// Marshal the form + active profile into the Qt-free command core. Shared
    /// by buildPerCoinCommand() and launch()'s reward-safety precheck.
    c2pool_qt::PerCoinParams marshalPerCoinParams() const;
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
    QComboBox* modeCombo_;       ///< integrated / sharechain / solo / custodial / standalone
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
    QCheckBox* dashdAttachCheck_{nullptr}; ///< DASH: attach external dashd (--coin-rpc/--coin-rpc-auth); default OFF = daemonless
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
    QLabel*        addressStatusLabel_{nullptr}; ///< inline wrong-coin / advisory notice
    QCheckBox*     autoDetectWalletCheck_; ///< --auto-detect-wallet (default on)
    QDoubleSpinBox* feeSpinBox_;        ///< -f / --fee (node-owner fee %)
    QDoubleSpinBox* giveAuthorSpinBox_; ///< --give-author (dev donation %)
    QCheckBox*     giveAuthorZeroAckCheck_{nullptr}; ///< explicit 0% opt-in (reward-safety ack)
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

    // ── PerCoinRun run-loop controls (DASH/DGB/BCH; catalog-gated per binary) ─
    QGroupBox* runLoopGroup_{nullptr};        ///< shown only for PerCoinRun coins
    QCheckBox* coinP2pDiscoverCheck_{nullptr};///< --coin-p2p-discover (transport, reward-neutral)
    QCheckBox* noP2pRelayCheck_{nullptr};     ///< --no-p2p-relay (DASH/DGB)
    QLineEdit* bchAnchorEdit_{nullptr};       ///< --anchor H:HASH (BCH cold-start ABLA floor)

    // ── ★ Advanced / embedded coin-network (transport + gate-lift) ───────────
    // Opt-in, default OFF. This is the ONLY place --coin-p2p-connect /
    // --embedded-mainnet may be emitted. DASH runs the embedded arm by default
    // when daemonless (bare --run, --embedded-mainnet ON in the node); these
    // controls only pin peers or force the flag explicitly (needed when dashd is
    // attached, where it defaults OFF).
    QGroupBox*      embeddedGroup_{nullptr};
    QCheckBox*      embeddedP2pCheck_{nullptr};   ///< enables --coin-p2p-connect (default OFF)
    QPlainTextEdit* embeddedP2pPeersEdit_{nullptr}; ///< HOST:PORT per line
    QCheckBox*      embeddedMainnetCheck_{nullptr}; ///< enables --embedded-mainnet (default OFF, DASH)
    QLabel*         embeddedWarnLabel_{nullptr};
    // Embedded coin-network producer target (DGB --coin-daemon + --coin-magic +
    // --coin-genesis). Emitted ONLY when embeddedP2pCheck_ is on.
    QLineEdit*      embeddedCoinDaemonEdit_{nullptr};  ///< --coin-daemon HOST:PORT (DGB)
    QLineEdit*      embeddedCoinMagicEdit_{nullptr};   ///< --coin-magic / --coin-p2p-magic HEX
    QLineEdit*      embeddedCoinGenesisEdit_{nullptr}; ///< --coin-genesis HASH (DGB)

    // ── Command Preview ─────────────────────────────────────────────────────
    QTextEdit*   cmdPreview_;
    QPushButton* buildPreviewBtn_;
    QPushButton* launchBtn_;
    QPushButton* stopBtn_;
    QPushButton* restartBtn_;
};