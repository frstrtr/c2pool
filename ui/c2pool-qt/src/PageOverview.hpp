#pragma once

#include "ApiClient.hpp"

#include <QLabel>
#include <QWidget>

class PageOverview : public QWidget
{
    Q_OBJECT
public:
    explicit PageOverview(QWidget* parent = nullptr);

    void refresh(ApiClient* api);

private:
    QLabel* uptimeValue_;
    QLabel* poolHashrateValue_;
    QLabel* staleRateValue_;
    QLabel* networkDiffValue_;
    QLabel* chainHeightValue_;
    QLabel* sharesValue_;
    QLabel* uniqueMinersValue_;
    QLabel* peersValue_;

    // Enhanced stats
    QLabel* luckValue_;
    QLabel* v36StatusValue_;
    QLabel* broadcasterValue_;
    QLabel* mergedStatsValue_;

    QLabel* statusValue_;
};
