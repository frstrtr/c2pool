// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// PageImport — the "Import / Load Key" screen (design §3, phases M1-A / M1-X).
//
// SLICE 1 (read/construct only): accepts the key formats the merged offline
// libraries support and DISPLAYS the derived public addresses. No signing.
//
//   Family A (Bitcoin-script, c2wallet-hdkeys):
//     * BIP39 mnemonic (+ optional passphrase) -> real checksum verify -> seed
//       -> BIP32 master -> BIP44/49/84/86 derivation grid -> address candidates
//     * WIF                (decode_wif)
//     * raw hex privkey    (decode_raw_hex, 1 <= k < N range check)
//     * BIP32 xprv / xpub  (HDKey::parse; xpub => watch-only)
//   Family B (Monero, c2wallet_monero):
//     * 25-word (or 24-word) Monero mnemonic -> {spend,view} keys -> primary
//       address + a few subaddresses
//
// All secret material stays in the zeroizing SecureBytes / MoneroKeys the
// libraries return; this page only renders the resulting PUBLIC addresses.

#include <QWidget>

class QComboBox;
class QLineEdit;
class QCheckBox;
class QLabel;
class QPlainTextEdit;
class QPushButton;

class PageImport : public QWidget
{
    Q_OBJECT
public:
    explicit PageImport(QWidget* parent = nullptr);

private slots:
    void onFormatChanged();
    void onImport();

private:
    void deriveFamilyA_bip39();
    void deriveFamilyA_wif();
    void deriveFamilyA_rawhex();
    void deriveFamilyA_extkey();
    void deriveFamilyB_monero();

    QComboBox*      formatCombo_{nullptr};
    QComboBox*      coinCombo_{nullptr};
    QLineEdit*      secretEdit_{nullptr};
    QLabel*         passphraseLabel_{nullptr};
    QLineEdit*      passphraseEdit_{nullptr};
    QCheckBox*      compressedCheck_{nullptr};
    QLabel*         coinLabel_{nullptr};
    QPushButton*    importBtn_{nullptr};
    QPlainTextEdit* output_{nullptr};
};
