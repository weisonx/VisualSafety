#pragma once

#include <QObject>
#include <QVariantList>

class SecurityController final : public QObject
{
    Q_OBJECT
    Q_PROPERTY(QVariantList permissions READ permissions NOTIFY dataChanged)
    Q_PROPERTY(QVariantList appPermissions READ appPermissions NOTIFY dataChanged)
    Q_PROPERTY(QVariantList highRiskPermissions READ highRiskPermissions NOTIFY dataChanged)
    Q_PROPERTY(QVariantList credentials READ credentials NOTIFY dataChanged)
    Q_PROPERTY(QVariantList ports READ ports NOTIFY dataChanged)
    Q_PROPERTY(QVariantList firewallRules READ firewallRules NOTIFY dataChanged)
    Q_PROPERTY(QVariantList traffic READ traffic NOTIFY dataChanged)
    Q_PROPERTY(QVariantList alerts READ alerts NOTIFY dataChanged)
    Q_PROPERTY(QVariantList logs READ logs NOTIFY logsChanged)
    Q_PROPERTY(QVariantList appMonitors READ appMonitors NOTIFY dataChanged)
    Q_PROPERTY(QString lastAction READ lastAction NOTIFY statusChanged)
    Q_PROPERTY(int criticalAlertCount READ criticalAlertCount NOTIFY dataChanged)
    Q_PROPERTY(int runningAppCount READ runningAppCount NOTIFY dataChanged)
    Q_PROPERTY(int blockedActionCount READ blockedActionCount NOTIFY dataChanged)
    Q_PROPERTY(bool desktopNotify READ desktopNotify WRITE setDesktopNotify NOTIFY notifySettingsChanged)
    Q_PROPERTY(bool emailNotify READ emailNotify WRITE setEmailNotify NOTIFY notifySettingsChanged)
    Q_PROPERTY(bool smsNotify READ smsNotify WRITE setSmsNotify NOTIFY notifySettingsChanged)

public:
    explicit SecurityController(QObject *parent = nullptr);

    QVariantList permissions() const;
    QVariantList appPermissions() const;
    QVariantList highRiskPermissions() const;
    QVariantList credentials() const;
    QVariantList ports() const;
    QVariantList firewallRules() const;
    QVariantList traffic() const;
    QVariantList alerts() const;
    QVariantList logs() const;
    QVariantList appMonitors() const;
    QString lastAction() const;
    int criticalAlertCount() const;
    int runningAppCount() const;
    int blockedActionCount() const;

    bool desktopNotify() const;
    void setDesktopNotify(bool value);
    bool emailNotify() const;
    void setEmailNotify(bool value);
    bool smsNotify() const;
    void setSmsNotify(bool value);

    Q_INVOKABLE void refreshData();
    Q_INVOKABLE void forceQuitApp(const QString &name);
    Q_INVOKABLE void blockAction(const QString &source, const QString &action);
    Q_INVOKABLE void shutdownNow();
    Q_INVOKABLE void restartNow();
    Q_INVOKABLE void addManualLog(const QString &level, const QString &message);

signals:
    void dataChanged();
    void logsChanged();
    void statusChanged();
    void notifySettingsChanged();

private:
    void appendLog(const QString &level, const QString &message);
    void appendAlert(const QString &severity, const QString &title, const QString &detail);
    QString nowStamp() const;

    QVariantList m_permissions;
    QVariantList m_appPermissions;
    QVariantList m_highRiskPermissions;
    QVariantList m_credentials;
    QVariantList m_ports;
    QVariantList m_firewallRules;
    QVariantList m_traffic;
    QVariantList m_alerts;
    QVariantList m_logs;
    QVariantList m_appMonitors;
    QString m_lastAction;
    int m_blockedActionCount = 0;
    bool m_desktopNotify = true;
    bool m_emailNotify = true;
    bool m_smsNotify = false;
};
