#pragma once

#include <QObject>
#include <QSet>
#include <QString>
#include <QVariantList>
#include <QVariantMap>

class SecurityController final : public QObject
{
    Q_OBJECT
    Q_PROPERTY(QVariantList permissions READ permissions NOTIFY dataChanged)
    Q_PROPERTY(QVariantList appPermissions READ appPermissions NOTIFY dataChanged)
    Q_PROPERTY(QVariantList highRiskPermissions READ highRiskPermissions NOTIFY dataChanged)
    Q_PROPERTY(QVariantList credentials READ credentials NOTIFY dataChanged)
    Q_PROPERTY(QVariantList ports READ ports NOTIFY dataChanged)
    Q_PROPERTY(QVariantList publicExposure READ publicExposure NOTIFY dataChanged)
    Q_PROPERTY(QVariantList ipAddresses READ ipAddresses NOTIFY dataChanged)
    Q_PROPERTY(QVariantList firewallRules READ firewallRules NOTIFY dataChanged)
    Q_PROPERTY(QVariantMap controls READ controls NOTIFY dataChanged)
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
    Q_PROPERTY(QString smtpServer READ smtpServer WRITE setSmtpServer NOTIFY notifySettingsChanged)
    Q_PROPERTY(int smtpPort READ smtpPort WRITE setSmtpPort NOTIFY notifySettingsChanged)
    Q_PROPERTY(QString smtpSender READ smtpSender WRITE setSmtpSender NOTIFY notifySettingsChanged)
    Q_PROPERTY(QString smtpRecipient READ smtpRecipient WRITE setSmtpRecipient NOTIFY notifySettingsChanged)
    Q_PROPERTY(QString smsWebhookUrl READ smsWebhookUrl WRITE setSmsWebhookUrl NOTIFY notifySettingsChanged)
    Q_PROPERTY(QString smsRecipient READ smsRecipient WRITE setSmsRecipient NOTIFY notifySettingsChanged)
    Q_PROPERTY(bool autoBlockHighRiskPorts READ autoBlockHighRiskPorts WRITE setAutoBlockHighRiskPorts NOTIFY policyChanged)
    Q_PROPERTY(bool autoKillUntrustedShell READ autoKillUntrustedShell WRITE setAutoKillUntrustedShell NOTIFY policyChanged)
    Q_PROPERTY(QString processWhitelist READ processWhitelist WRITE setProcessWhitelist NOTIFY policyChanged)
    Q_PROPERTY(QString processBlacklist READ processBlacklist WRITE setProcessBlacklist NOTIFY policyChanged)
    Q_PROPERTY(QVariantList availablePlugins READ availablePlugins NOTIFY pluginsChanged)
    Q_PROPERTY(QVariantList installedPlugins READ installedPlugins NOTIFY pluginsChanged)

public:
    explicit SecurityController(QObject *parent = nullptr);

    QVariantList permissions() const;
    QVariantList appPermissions() const;
    QVariantList highRiskPermissions() const;
    QVariantList credentials() const;
    QVariantList ports() const;
    QVariantList publicExposure() const;
    QVariantList ipAddresses() const;
    QVariantList firewallRules() const;
    QVariantMap controls() const;
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
    QString smtpServer() const;
    void setSmtpServer(const QString &value);
    int smtpPort() const;
    void setSmtpPort(int value);
    QString smtpSender() const;
    void setSmtpSender(const QString &value);
    QString smtpRecipient() const;
    void setSmtpRecipient(const QString &value);
    QString smsWebhookUrl() const;
    void setSmsWebhookUrl(const QString &value);
    QString smsRecipient() const;
    void setSmsRecipient(const QString &value);

    bool autoBlockHighRiskPorts() const;
    void setAutoBlockHighRiskPorts(bool value);
    bool autoKillUntrustedShell() const;
    void setAutoKillUntrustedShell(bool value);
    QString processWhitelist() const;
    void setProcessWhitelist(const QString &value);
    QString processBlacklist() const;
    void setProcessBlacklist(const QString &value);

    QVariantList availablePlugins() const;
    QVariantList installedPlugins() const;

    Q_INVOKABLE void refreshData();
    Q_INVOKABLE void forceQuitApp(const QString &name);
    Q_INVOKABLE void blockAction(const QString &source, const QString &action);
    Q_INVOKABLE void shutdownNow();
    Q_INVOKABLE void restartNow();
    Q_INVOKABLE void addManualLog(const QString &level, const QString &message);
    Q_INVOKABLE void testNotifications();
    Q_INVOKABLE void applyPolicyNow();
    Q_INVOKABLE bool exportLogs(const QString &filePath);
    Q_INVOKABLE void hardenFirewall();
    Q_INVOKABLE void setRemoteDesktopEnabled(bool enabled);
    Q_INVOKABLE void setFileSharingEnabled(bool enabled);
    Q_INVOKABLE void disableSmb1();
    Q_INVOKABLE void restartAsAdmin();
    Q_INVOKABLE bool installPlugin(const QString &id);
    Q_INVOKABLE bool uninstallPlugin(const QString &id);
    Q_INVOKABLE QVariantMap runPlugin(const QString &id, const QVariantMap &params);
    Q_INVOKABLE QString knownPortTip(int port, const QString &protocol) const;
    Q_INVOKABLE QString knownProcessTip(const QString &processName) const;

signals:
    void dataChanged();
    void logsChanged();
    void statusChanged();
    void notifySettingsChanged();
    void policyChanged();
    void pluginsChanged();

private:
    bool isRunningAsAdmin() const;
    QString nowStamp() const;
    QString sanitizeRuleName(const QString &value) const;
    QString psQuote(const QString &value) const;
    QStringList splitCsvValues(const QString &value) const;
    bool containsInCsv(const QString &csv, const QString &name) const;
    bool isSensitiveShellProcess(const QString &name) const;
    bool isBlacklisted(const QString &name) const;
    bool isWhitelisted(const QString &name) const;
    bool blockPort(int port, QString *detail);
    bool terminateProcess(const QString &name, QString *detail);
    void sendDesktopNotification(const QString &title, const QString &detail);
    void sendEmailNotification(const QString &title, const QString &detail);
    void sendSmsNotification(const QString &title, const QString &detail);
    void runPolicyEngine();

    void appendLog(const QString &level, const QString &message);
    void appendAlert(const QString &severity, const QString &title, const QString &detail);

    QString pluginConfigPath() const;
    void loadPlugins();
    void savePlugins() const;
    QVariantMap findPluginById(const QString &id) const;
    void rebuildInstalledPlugins();

    QVariantList scanAppMonitors() const;
    QVariantList scanPrivileges(bool isAdmin) const;
    QVariantList scanPorts(const QVariantList &apps) const;
    QVariantList scanIpAddresses() const;
    QVariantList scanPublicExposure(const QVariantList &ports, const QVariantList &firewallRules, const QVariantList &ipAddresses) const;
    QVariantList scanCredentials() const;
    QVariantList scanFirewallRules() const;
    QVariantMap scanControls(const QVariantList &firewallRules, bool isAdmin) const;
    QVariantList scanTraffic() const;
    QVariantList scanEventAlerts() const;
    QVariantList deriveAppPermissions(const QVariantList &apps, const QVariantList &ports) const;
    QVariantList deriveHighRiskPermissions(const QVariantList &apps, const QVariantList &ports) const;
    QVariantList annotateAppMonitors(const QVariantList &apps, const QVariantList &ports) const;
    QVariantList derivePermissions(const QVariantList &firewallRules, bool isAdmin) const;
    QVariantList deriveAlerts(const QVariantList &highRiskPermissions, const QVariantList &traffic) const;

    QVariantList m_permissions;
    QVariantList m_appPermissions;
    QVariantList m_highRiskPermissions;
    QVariantList m_credentials;
    QVariantList m_ports;
    QVariantList m_publicExposure;
    QVariantList m_ipAddresses;
    QVariantList m_firewallRules;
    QVariantMap m_controls;
    QVariantList m_traffic;
    QVariantList m_alerts;
    QVariantList m_logs;
    QVariantList m_appMonitors;
    QString m_lastAction;
    QString m_logFilePath;
    int m_blockedActionCount = 0;
    bool m_desktopNotify = true;
    bool m_emailNotify = true;
    bool m_smsNotify = false;
    QString m_smtpServer;
    int m_smtpPort = 25;
    QString m_smtpSender;
    QString m_smtpRecipient;
    QString m_smsWebhookUrl;
    QString m_smsRecipient;
    bool m_autoBlockHighRiskPorts = true;
    bool m_autoKillUntrustedShell = false;
    QString m_processWhitelist = "explorer.exe,svchost.exe,msmpeng.exe";
    QString m_processBlacklist = "powershell.exe,pwsh.exe,cmd.exe,wscript.exe,cscript.exe,mshta.exe";
    QSet<int> m_policyBlockedPorts;
    QSet<QString> m_policyTerminatedApps;

    QVariantList m_availablePlugins;
    QVariantList m_installedPlugins;
    QSet<QString> m_installedPluginIds;
};
