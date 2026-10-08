// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// PageAirGap — the "Air-Gap Transfer" screen (design docs/design/c2wallet-qt.md
// §5.4; M6 slice-2c). The transport surface for moving the transfer artifacts
// across the diode, in BOTH families and all three directions the offline
// signer needs:
//
//   * IMPORT unsigned  (online  -> offline): receive the constructed artifact.
//   * EXPORT signed    (offline -> online):  emit the finished signed tx for
//                                            the c2pool loader.
//   * EXPORT unsigned  (offline-built -> online): carry an offline-built
//                                            unsigned artifact online for a
//                                            validate dry-run.
//
// It MARSHALS bytes only — it never signs (there is no key code here). Two
// transports: a file (QFile) and a multi-frame animated QR (GAP-8), rendered
// with QPainter from the embedded nayuki qrcodegen encoder. There is NO CAMERA
// (QtMultimedia would drag in Qt6::Network and break the link-guard), so QR
// INPUT is paste / file / keyboard-wedge frame TEXT only, decoded by qr_decode.
//
// Safety surfaces this page owns:
//   * the corruption-detection ladder (QR per-frame sha256 -> container magic/
//     version/TLV bounds -> GAP-3 R_DIGEST -> Monero keccak footer -> the human
//     sha256d / keccak digest compare), with the honest residual limit stated;
//   * the UNSIGNED <-> SIGNED confusion guard (two visually distinct slots; a
//     signed line must deserialize as a tx with a scriptSig/witness on every
//     input and must NOT start with the C2WU magic; the unsigned slot requires
//     the C2WU magic).

#include <QWidget>

#include <cstdint>
#include <string>
#include <vector>

class QComboBox;
class QGroupBox;
class QLabel;
class QPlainTextEdit;
class QPushButton;
class QTimer;

class PageAirGap : public QWidget
{
    Q_OBJECT
public:
    explicit PageAirGap(QWidget* parent = nullptr);
    ~PageAirGap() override;

private slots:
    void onModeChanged();   // family / direction selector changed
    void onLoadFile();
    void onDecode();        // run the ladder + confusion guard on the input
    void onSaveExport();
    void onCopyFrames();
    void onToggleAnim();
    void onTick();          // advance the animated-QR frame

private:
    // 0 = Bitcoin-script (A), 1 = Monero (B)
    int  family() const;
    // 0 = Import unsigned, 1 = Export signed, 2 = Export unsigned
    int  direction() const;
    bool isSignedSlot() const;   // direction 1
    void resetValidated();
    void showFrame(int i);

    QComboBox*      familyCombo_{nullptr};
    QComboBox*      dirCombo_{nullptr};

    QGroupBox*      inputBox_{nullptr};
    QLabel*         slotBadge_{nullptr};
    QPlainTextEdit* inputEdit_{nullptr};
    QPushButton*    loadBtn_{nullptr};
    QPushButton*    decodeBtn_{nullptr};

    QLabel*         cardLabel_{nullptr};

    QGroupBox*      exportBox_{nullptr};
    QLabel*         qrView_{nullptr};
    QLabel*         frameLabel_{nullptr};
    QPushButton*    animBtn_{nullptr};
    QPushButton*    copyFramesBtn_{nullptr};
    QPushButton*    saveBtn_{nullptr};
    QTimer*         qrTimer_{nullptr};

    // Validated state
    bool                     validated_{false};
    std::vector<uint8_t>     payload_;   // the exact bytes to save + frame
    std::vector<std::string> frames_;    // qr_encode text frames of payload_
    int                      curFrame_{0};
};
