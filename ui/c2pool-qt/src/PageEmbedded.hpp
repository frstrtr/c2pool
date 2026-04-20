// PageEmbedded — generic QWebEngineView host.
//
// One C++ class serves every embedded-web page; configuration differs
// per page. Per frstrtr/the/docs/c2pool-qt-hybrid-architecture.md §4
// (class shape) and §8 step 2 (skeleton-only scope for this commit).
//
// This commit ships the skeleton: Config struct, view + channel
// setup, qrc:/// loading, dev-mode filesystem override, F5 reload.
// Bridge objects wire through QWebChannel but the real SharechainBridge
// / SettingsBridge / CoinBridge classes land in subsequent steps.
//
// Hazards (delta v1 §E) addressed here:
//  - Thread affinity: view + channel + bridge registration all run on
//    the GUI thread; PageEmbedded inherits QWidget's thread affinity.
//  - Shutdown ordering: destroyView() disconnects the channel, deletes
//    the view, and nulls the members. Full JS-side controller.destroy()
//    handshake lands with step 7 when a real controller exists.
//  - Dynamic URL handling: navigation requests to external origins are
//    routed to QDesktopServices::openUrl (the view stays anchored to
//    its bundle origin).
//  - Reload loop: reload() calls destroyView() first, then recreates
//    the view + channel + bridges fresh, preventing dangling subscribers.
//  - CSP: inline meta tag in the loaded HTML (deferred — step 7 ships
//    the real dashboard-embed.html with the production CSP).

#pragma once

#include <QList>
#include <QObject>
#include <QString>
#include <QWidget>

class QWebEngineView;
class QWebChannel;

class PageEmbedded : public QWidget {
    Q_OBJECT
public:
    struct Config {
        /** qrc:// URL for the page. In dev mode (C2POOL_QT_DEV_BUNDLE
         *  compile flag + C2POOL_QT_BUNDLE_DIR env var set), this is
         *  rewritten to file://$DIR/<basename>. */
        QString qrcUrl;
        /** QObjects registered on the channel under `bridgeObjectName`.
         *  Each must outlive the PageEmbedded instance — typically
         *  they live on MainWindow. */
        QList<QObject*> bridges;
        /** JS global under which the bridge becomes accessible:
         *  `<bridgeObjectName>.<bridge.objectName()>`. */
        QString bridgeObjectName = QStringLiteral("qtBridge");
        /** Enable F5 to reload + DevTools (Ctrl+Shift+I). Default off
         *  in release builds; dev harness sets true. */
        bool devReloadEnabled = false;
    };

    explicit PageEmbedded(const Config& cfg, QWidget* parent = nullptr);
    ~PageEmbedded() override;

    /** Reload the page. Runs the destroy fence first so any live
     *  subscriptions are torn down before the new page bootstraps. */
    void reload();

    /** Destroy the embedded view — disconnect channel, delete the
     *  view, null members. Safe to call from either the destructor
     *  or before explicit reload. Idempotent. */
    void destroyView();

protected:
    void keyPressEvent(QKeyEvent* ev) override;

private:
    /** Resolve qrcUrl → an effective URL, applying the dev-bundle
     *  filesystem override when enabled + env var is set. */
    QString effectiveUrl() const;

    /** Build view + channel + register bridges, then load the URL. */
    void buildView();

    Config cfg_;
    QWebEngineView* view_ = nullptr;
    QWebChannel* channel_ = nullptr;
};
