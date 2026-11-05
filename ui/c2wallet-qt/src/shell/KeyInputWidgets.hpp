// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// KeyInputWidgets — the key-import block shared by PageDashInject (stage 4)
// and PageSignMessage (stage 3), so the two key-bearing pages cannot drift:
// format combo (BIP39 mnemonic / WIF / BIP38 / descriptor / JSON keystore),
// password-mode secret and passphrase edits, the scan range (accounts,
// indices, internal chain, uncompressed keys).
//
// Secret hygiene: read() takes each secret ONCE, clears its widget at once and
// moves it into the caller's KeyInput, which the caller wipes with
// KeyInputWipe when the bind attempt ends. A keystore file chosen at bind time
// is read into the KeyInput and its QByteArray is wiped. No QSettings, no
// clipboard. This TU includes ONLY the std-only DASH model header (G3 rule).

#include "family/bitcoin/dash/DashInjectModel.hpp" // KeyInput, KeySource (std-only)

#include <QObject>
#include <QString>

class QCheckBox;
class QComboBox;
class QLineEdit;
class QSpinBox;
class QVBoxLayout;
class QWidget;

// Wipes a KeyInput's two secret strings when the bind attempt ends.
struct KeyInputWipe {
    c2w::dash::KeyInput& k;
    ~KeyInputWipe();
};

class KeyInputWidgets : public QObject
{
public:
    // Builds the block into `into`; the widgets are children of `parent`, and so
    // is this object (deleted with them).
    KeyInputWidgets(QWidget* parent, QVBoxLayout* into);

    // Fill `out` from the widgets (clearing both secret edits). A JSON keystore
    // with an empty secret field opens a file chooser on `dialogParent`.
    // Returns false when there is nothing to bind: the chooser was cancelled
    // (*error stays empty) or the file could not be read (*error says so).
    bool read(QWidget* dialogParent, c2w::dash::KeyInput& out, QString* error);

private:
    void onSourceChanged();

    QComboBox* srcCombo_{nullptr};
    QLineEdit* secretEdit_{nullptr};
    QLineEdit* passEdit_{nullptr};
    QSpinBox*  accountsSpin_{nullptr};
    QSpinBox*  indicesSpin_{nullptr};
    QCheckBox* internalChk_{nullptr};
    QCheckBox* uncompChk_{nullptr};
};
