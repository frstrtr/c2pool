#include "PageEmbedded.hpp"

#include <QDesktopServices>
#include <QDir>
#include <QFileInfo>
#include <QKeyEvent>
#include <QProcessEnvironment>
#include <QUrl>
#include <QVBoxLayout>
#include <QWebChannel>
#include <QWebEnginePage>
#include <QWebEngineProfile>
#include <QWebEngineSettings>
#include <QWebEngineView>

#ifdef C2POOL_QT_DEV_BUNDLE
#  include <QFileSystemWatcher>
#endif

// External-URL router: intercept navigation attempts to origins other
// than the bundle's own qrc:/// (or its dev-mode file://) and hand
// them to the OS default browser. Keeps the embedded view anchored
// to the shipped bundle.
namespace {

class BundleAnchoredPage : public QWebEnginePage {
public:
    explicit BundleAnchoredPage(const QUrl& bundleOrigin, QWebEngineProfile* profile,
                                QObject* parent = nullptr)
        : QWebEnginePage(profile, parent), origin_(bundleOrigin) {}

protected:
    bool acceptNavigationRequest(const QUrl& url, NavigationType type, bool /*isMainFrame*/) override
    {
        // Internal navigation (same origin, same base path) → allow.
        if (url.scheme() == origin_.scheme()) {
            if (url.scheme() == QStringLiteral("qrc")) return true;
            if (url.scheme() == QStringLiteral("file")) {
                // Allow any file:// under the bundle directory.
                return url.toLocalFile().startsWith(QFileInfo(origin_.toLocalFile()).absolutePath());
            }
        }
        // Everything else (http, https, mailto, ...) — hand off to OS.
        if (type == NavigationTypeLinkClicked) {
            QDesktopServices::openUrl(url);
        }
        return false;
    }

private:
    QUrl origin_;
};

} // namespace

PageEmbedded::PageEmbedded(const Config& cfg, QWidget* parent)
    : QWidget(parent), cfg_(cfg)
{
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    setLayout(layout);
    buildView();
}

PageEmbedded::~PageEmbedded()
{
    destroyView();
}

QString PageEmbedded::effectiveUrl() const
{
#ifdef C2POOL_QT_DEV_BUNDLE
    const auto env = QProcessEnvironment::systemEnvironment();
    const QString devDir = env.value(QStringLiteral("C2POOL_QT_BUNDLE_DIR"));
    if (!devDir.isEmpty()) {
        const QString basename = QFileInfo(QUrl(cfg_.qrcUrl).path()).fileName();
        const QString localPath = QDir(devDir).filePath(basename);
        if (QFileInfo::exists(localPath)) {
            return QUrl::fromLocalFile(localPath).toString();
        }
    }
#endif
    return cfg_.qrcUrl;
}

void PageEmbedded::buildView()
{
    view_ = new QWebEngineView(this);
    auto* profile = QWebEngineProfile::defaultProfile();
    const QUrl bundleUrl(effectiveUrl());
    auto* page = new BundleAnchoredPage(bundleUrl, profile, view_);
    view_->setPage(page);

    if (cfg_.devReloadEnabled) {
        page->settings()->setAttribute(QWebEngineSettings::JavascriptEnabled, true);
        page->settings()->setAttribute(QWebEngineSettings::LocalContentCanAccessFileUrls, true);
        page->settings()->setAttribute(QWebEngineSettings::LocalContentCanAccessRemoteUrls, false);
    }

    channel_ = new QWebChannel(this);
    for (QObject* bridge : cfg_.bridges) {
        if (bridge == nullptr || bridge->objectName().isEmpty()) continue;
        channel_->registerObject(bridge->objectName(), bridge);
    }
    page->setWebChannel(channel_);

    // Inject the bridge top-level global — qtBridge.<objectName> for
    // each registered bridge. JS uses this plus qwebchannel.js (shipped
    // with Qt and exposed via qrc:///qtwebchannel/qwebchannel.js when
    // the WebChannel profile is configured).
    view_->setUrl(bundleUrl);

    auto* boxLayout = qobject_cast<QVBoxLayout*>(layout());
    if (boxLayout != nullptr) {
        boxLayout->addWidget(view_);
    }
}

void PageEmbedded::reload()
{
    destroyView();
    buildView();
}

void PageEmbedded::destroyView()
{
    if (channel_ != nullptr) {
        channel_->deregisterObject(nullptr);
        channel_->deleteLater();
        channel_ = nullptr;
    }
    if (view_ != nullptr) {
        view_->setPage(nullptr);
        view_->deleteLater();
        view_ = nullptr;
    }
}

void PageEmbedded::keyPressEvent(QKeyEvent* ev)
{
    if (cfg_.devReloadEnabled && ev != nullptr && ev->key() == Qt::Key_F5) {
        reload();
        ev->accept();
        return;
    }
    QWidget::keyPressEvent(ev);
}
