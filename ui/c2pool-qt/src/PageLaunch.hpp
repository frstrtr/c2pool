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
    /** Return the QSettings group prefix the form persists to:
     *  "profiles/<active>/launch" when settings_ is set,
     *  "launch" otherwise. */
    QString launchGroupPath() const;

    SettingsStore* settings_{nullptr};
    QProcess* process_;

    // ── Mode / Network ──────────────────────────────────────────────────────
    QComboBox* modeCombo_;       ///< integrated / sharechain / solo
    QCheckBox* testnetCheck_;
    QComboBox* chainCombo_;      ///< litecoin / bitcoin / dogecoin

    // ── Executable ─────────────────────────────────────────────────────────
    QLineEdit* binaryEdit_;

    // ── Ports ───────────────────────────────────────────────────────────────
    QSpinBox*  p2pPortSpin_;
    QSpinBox*  stratumPortSpin_;
    QSpinBox*  httpPortSpin_;

    // ── Parent Coin Daemon ──────────────────────────────────────────────────
    QLineEdit* coindHostEdit_;
    QSpinBox*  coindPortSpin_;       ///< 0 = auto-detect from chain
    QLineEdit* rpcUserEdit_;
    QLineEdit* rpcPassEdit_;
    QSpinBox*  coindP2pPortSpin_;    ///< --coind-p2p-port
    QLineEdit* coindP2pAddrEdit_;    ///< --coind-p2p-address

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

    // ── Command Preview ─────────────────────────────────────────────────────
    QTextEdit*   cmdPreview_;
    QPushButton* buildPreviewBtn_;
    QPushButton* launchBtn_;
    QPushButton* stopBtn_;
    QPushButton* restartBtn_;
};
