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
// Secret handling: the input QLineEdits are cleared after each action, and the
// intermediate std::string carrying the secret is securely wiped as it leaves
// scope. The library key material stays in the zeroizing SecureBytes / MoneroKeys
// the libraries return; this page only renders the resulting PUBLIC addresses.

#include <QWidget>

#include <string>

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
    // The secret is read once in onImport(), wiped there, and passed in by
    // const-ref so no method re-reads plaintext from the widget.
    void deriveFamilyA_bip39(const std::string& mnemonic, const std::string& passphrase);
    void deriveFamilyA_wif(const std::string& wif);
    void deriveFamilyA_rawhex(const std::string& hex);
    void deriveFamilyA_extkey(const std::string& ext);
    void deriveFamilyB_monero(const std::string& phrase);

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
