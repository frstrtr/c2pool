#pragma once

#include "NodeManager.hpp"

#include <QCheckBox>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QPushButton>
#include <QWidget>

/// Node profile management page.
///
/// Add, edit, remove, and test node connection profiles.
/// Each profile can be local (manage daemon + config files)
/// or remote (connect via REST API + auth token).
class PageSettings : public QWidget
{
    Q_OBJECT
public:
    explicit PageSettings(NodeManager* manager, QWidget* parent = nullptr);

    void refresh();

signals:
    void profilesChanged();

private slots:
    void addProfile();
    void removeProfile();
    void saveCurrentProfile();
    void testConnection();
    void onProfileSelected(int row);

private:
    void populateForm(const NodeProfile& profile);
    void clearForm();

    NodeManager* manager_;

    QListWidget* profileList_;
    QPushButton* addBtn_;
    QPushButton* removeBtn_;
    QPushButton* testBtn_;

    // Form fields
    QLineEdit* labelEdit_;
    QLineEdit* addressEdit_;
    QLineEdit* authTokenEdit_;
    QLineEdit* dataDirEdit_;
    QCheckBox* isLocalCheck_;
    QCheckBox* autoConnectCheck_;
    QCheckBox* autoLaunchCheck_;
    QPushButton* readCookieBtn_;
    QPushButton* saveBtn_;
    QLabel* statusLabel_;

    QString currentProfileId_;
};
