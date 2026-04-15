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

/// Daemon launch-configuration page.
///
/// Provides a complete GUI form covering every important c2pool CLI flag:
///   • Operation mode (integrated / sharechain / solo)
///   • Network (litecoin / bitcoin / dogecoin, testnet toggle)
///   • Binary path + ports (P2P, stratum, HTTP API)
///   • Parent coin-daemon RPC credentials
///   • Payout address, node-owner fee (-f), dev donation (--give-author)
///   • Redistribute mode for invalid-address miners (--redistribute)
///   • Merged-mining chains table (--merged SYMBOL:CHAIN_ID:HOST:PORT:USER:PASS[:P2P])
///   • Generated-command preview
///   • Launch / Stop / Restart daemon buttons
///
/// The widget owns its own QProcess so MainWindow toolbar buttons simply
/// delegate to launch() / stop() / restart().
class PageLaunch : public QWidget
{
    Q_OBJECT
public:
    explicit PageLaunch(QWidget* parent = nullptr);

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

    QProcess* process_;

    // ── Mode / Network ──────────────────────────────────────────────────────
    QComboBox* modeCombo_;       ///< integrated / sharechain / solo
    QCheckBox* testnetCheck_;
    QComboBox* chainCombo_;      ///< litecoin / bitcoin / dogecoin
    QCheckBox* custodialCheck_;  ///< --custodial

    // ── Embedded SPV ────────────────────────────────────────────────────────
    QCheckBox* embeddedLtcCheck_;          ///< --embedded-ltc (default on)
    QCheckBox* embeddedDogeCheck_;         ///< --embedded-doge (default on)
    QCheckBox* dogeTestnet4Check_;         ///< --doge-testnet4alpha
    QLineEdit* headerCheckpointEdit_;      ///< --header-checkpoint H:HASH
    QLineEdit* dogeHeaderCheckpointEdit_;  ///< --doge-header-checkpoint H:HASH

    // ── Executable ─────────────────────────────────────────────────────────
    QLineEdit* binaryEdit_;

    // ── Ports ───────────────────────────────────────────────────────────────
    QSpinBox*  p2pPortSpin_;
    QSpinBox*  stratumPortSpin_;
    QSpinBox*  httpPortSpin_;

    // ── Stratum Tuning ──────────────────────────────────────────────────────
    QDoubleSpinBox* stratumMinDiffSpin_;     ///< --stratum-min-diff
    QDoubleSpinBox* stratumMaxDiffSpin_;     ///< --stratum-max-diff
    QDoubleSpinBox* stratumTargetTimeSpin_;  ///< --stratum-target-time
    QCheckBox*      vardiffCheck_;           ///< --no-vardiff (inverted)
    QSpinBox*       maxCoinbaseOutputsSpin_; ///< --max-coinbase-outputs

    // ── Parent Coin Daemon ──────────────────────────────────────────────────
    QLineEdit* coindHostEdit_;
    QSpinBox*  coindPortSpin_;       ///< 0 = auto-detect from chain
    QLineEdit* rpcUserEdit_;
    QLineEdit* rpcPassEdit_;
    QSpinBox*  coindP2pPortSpin_;    ///< --coind-p2p-port
    QLineEdit* coindP2pAddrEdit_;    ///< --coind-p2p-address
    QLineEdit* dogeP2pAddrEdit_;     ///< --doge-p2p-address
    QSpinBox*  dogeP2pPortSpin_;     ///< --doge-p2p-port

    // ── Payout & Fees ───────────────────────────────────────────────────────
    QLineEdit*     addressEdit_;
    QCheckBox*     autoDetectWalletCheck_; ///< --auto-detect-wallet (default on)
    QDoubleSpinBox* feeSpinBox_;        ///< -f / --fee (node-owner fee %)
    QDoubleSpinBox* giveAuthorSpinBox_; ///< --give-author (dev donation %)
    QLineEdit*     nodeOwnerAddrEdit_;
    QLineEdit*     nodeOwnerScriptEdit_; ///< --node-owner-script (hex)
    QLineEdit*     nodeOwnerMergedAddrEdit_; ///< --node-owner-merged-address
    QComboBox*     redistributeCombo_;  ///< pplns / fee / boost / donate
    QSpinBox*      payoutWindowSpin_;   ///< --payout-window (seconds)
    QSpinBox*      storageSaveIntervalSpin_; ///< --storage-save-interval (seconds)

    // ── Merged Mining ───────────────────────────────────────────────────────
    /// Columns: Symbol | Chain ID | Host | Port | User | Password | P2P Port
    QTableWidget* mergedTable_;
    QPushButton*  addMergedBtn_;
    QPushButton*  removeMergedBtn_;

    // ── Network Tuning ────────────────────────────────────────────────────
    QSpinBox*  maxConnsSpinBox_;   ///< --max-conns
    QPlainTextEdit* seedNodesEdit_;  ///< -n HOST:PORT (one per line)
    QLineEdit* httpHostEdit_;        ///< --http-host (bind address)

    // ── Logging ─────────────────────────────────────────────────────────────
    QComboBox* logLevelCombo_;       ///< --log-level
    QLineEdit* logFileEdit_;         ///< --log-file
    QSpinBox*  logRotationMbSpin_;   ///< --log-rotation-mb
    QSpinBox*  logMaxMbSpin_;        ///< --log-max-mb

    // ── Performance & Limits ────────────────────────────────────────────────
    QSpinBox*  p2pMaxPeersSpin_;     ///< --p2p-max-peers
    QSpinBox*  banDurationSpin_;     ///< --ban-duration (seconds)
    QSpinBox*  rssLimitMbSpin_;      ///< --rss-limit-mb
    QSpinBox*  cacheSharedHashesSpin_; ///< cache_max_shared_hashes
    QSpinBox*  cacheKnownTxsSpin_;   ///< cache_max_known_txs
    QSpinBox*  cacheRawSharesSpin_;  ///< cache_max_raw_shares

    // ── Web & CORS ──────────────────────────────────────────────────────────
    QLineEdit* externalIpEdit_;      ///< --external-ip
    QLineEdit* corsOriginEdit_;      ///< --cors-origin
    QLineEdit* dashboardDirEdit_;    ///< --dashboard-dir

    // ── Block Explorer ──────────────────────────────────────────────────────
    QCheckBox* explorerCheck_;           ///< explorer enable
    QLineEdit* explorerUrlEdit_;         ///< explorer_url
    QSpinBox*  explorerDepthLtcSpin_;    ///< explorer_depth_ltc
    QSpinBox*  explorerDepthDogeSpin_;   ///< explorer_depth_doge
    QLineEdit* addrExplorerPrefixEdit_;  ///< address_explorer_prefix
    QLineEdit* blockExplorerPrefixEdit_; ///< block_explorer_prefix
    QLineEdit* txExplorerPrefixEdit_;    ///< tx_explorer_prefix

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

    // ── Command Preview ─────────────────────────────────────────────────────
    QTextEdit*   cmdPreview_;
    QPushButton* buildPreviewBtn_;
    QPushButton* launchBtn_;
    QPushButton* stopBtn_;
    QPushButton* restartBtn_;
};
