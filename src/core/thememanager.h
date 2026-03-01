#pragma once

#include <QObject>

class ThemeManager final : public QObject
{
    Q_OBJECT
    Q_PROPERTY(bool darkTheme READ darkTheme WRITE setDarkTheme NOTIFY themeChanged)
    Q_PROPERTY(QString windowBg READ windowBg NOTIFY themeChanged)
    Q_PROPERTY(QString sidebarBg READ sidebarBg NOTIFY themeChanged)
    Q_PROPERTY(QString cardBg READ cardBg NOTIFY themeChanged)
    Q_PROPERTY(QString cardAltBg READ cardAltBg NOTIFY themeChanged)
    Q_PROPERTY(QString textPrimary READ textPrimary NOTIFY themeChanged)
    Q_PROPERTY(QString textSecondary READ textSecondary NOTIFY themeChanged)
    Q_PROPERTY(QString borderColor READ borderColor NOTIFY themeChanged)
    Q_PROPERTY(QString accentColor READ accentColor NOTIFY themeChanged)
    Q_PROPERTY(QString accentMuted READ accentMuted NOTIFY themeChanged)
    Q_PROPERTY(QString dangerColor READ dangerColor NOTIFY themeChanged)
    Q_PROPERTY(QString warningColor READ warningColor NOTIFY themeChanged)
    Q_PROPERTY(QString successColor READ successColor NOTIFY themeChanged)
    Q_PROPERTY(QString controlBg READ controlBg NOTIFY themeChanged)
    Q_PROPERTY(QString controlBgHover READ controlBgHover NOTIFY themeChanged)
    Q_PROPERTY(QString controlText READ controlText NOTIFY themeChanged)
    Q_PROPERTY(QString inputBg READ inputBg NOTIFY themeChanged)
    Q_PROPERTY(QString inputText READ inputText NOTIFY themeChanged)
    Q_PROPERTY(QString inputPlaceholder READ inputPlaceholder NOTIFY themeChanged)

public:
    explicit ThemeManager(QObject *parent = nullptr);

    bool darkTheme() const;
    void setDarkTheme(bool value);
    Q_INVOKABLE void toggleTheme();

    QString windowBg() const;
    QString sidebarBg() const;
    QString cardBg() const;
    QString cardAltBg() const;
    QString textPrimary() const;
    QString textSecondary() const;
    QString borderColor() const;
    QString accentColor() const;
    QString accentMuted() const;
    QString dangerColor() const;
    QString warningColor() const;
    QString successColor() const;
    QString controlBg() const;
    QString controlBgHover() const;
    QString controlText() const;
    QString inputBg() const;
    QString inputText() const;
    QString inputPlaceholder() const;

signals:
    void themeChanged();

private:
    bool m_darkTheme = true;
};
