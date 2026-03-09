#pragma once

#include <QObject>
#include <QJsonObject>
#include <QString>

class AppConfig final : public QObject
{
    Q_OBJECT
    Q_PROPERTY(QString wanIps READ wanIps WRITE setWanIps NOTIFY changed)
    Q_PROPERTY(bool portForwardEnabled READ portForwardEnabled WRITE setPortForwardEnabled NOTIFY changed)
    Q_PROPERTY(bool dmzEnabled READ dmzEnabled WRITE setDmzEnabled NOTIFY changed)
    Q_PROPERTY(QString forwardedPortsCsv READ forwardedPortsCsv WRITE setForwardedPortsCsv NOTIFY changed)
    Q_PROPERTY(bool tunnelEnabled READ tunnelEnabled WRITE setTunnelEnabled NOTIFY changed)
    Q_PROPERTY(QString tunnelPortsCsv READ tunnelPortsCsv WRITE setTunnelPortsCsv NOTIFY changed)

public:
    explicit AppConfig(QObject *parent = nullptr);

    QString wanIps() const;
    void setWanIps(const QString &value);

    bool portForwardEnabled() const;
    void setPortForwardEnabled(bool value);

    bool dmzEnabled() const;
    void setDmzEnabled(bool value);

    QString forwardedPortsCsv() const;
    void setForwardedPortsCsv(const QString &value);

    bool tunnelEnabled() const;
    void setTunnelEnabled(bool value);

    QString tunnelPortsCsv() const;
    void setTunnelPortsCsv(const QString &value);

    Q_INVOKABLE bool isIpMarkedPublic(const QString &ip, bool guessedPublic) const;
    Q_INVOKABLE void setIpMarkedPublic(const QString &ip, bool value);

signals:
    void changed();

private:
    QString configPath() const;
    void load();
    void save() const;
    QJsonObject rootObject() const;
    void setRootObject(const QJsonObject &root);

    QJsonObject m_root;
};

