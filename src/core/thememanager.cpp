#include "thememanager.h"

ThemeManager::ThemeManager(QObject *parent)
    : QObject(parent)
{
}

bool ThemeManager::darkTheme() const
{
    return m_darkTheme;
}

void ThemeManager::setDarkTheme(bool value)
{
    if (m_darkTheme == value) {
        return;
    }
    m_darkTheme = value;
    emit themeChanged();
}

void ThemeManager::toggleTheme()
{
    setDarkTheme(!m_darkTheme);
}

QString ThemeManager::windowBg() const { return m_darkTheme ? "#111821" : "#f1f5fb"; }
QString ThemeManager::sidebarBg() const { return m_darkTheme ? "#0b1118" : "#e4ecf7"; }
QString ThemeManager::cardBg() const { return m_darkTheme ? "#18222e" : "#ffffff"; }
QString ThemeManager::cardAltBg() const { return m_darkTheme ? "#223244" : "#eef4fc"; }
QString ThemeManager::textPrimary() const { return m_darkTheme ? "#e8f0fa" : "#122238"; }
QString ThemeManager::textSecondary() const { return m_darkTheme ? "#99a9bb" : "#4f647d"; }
QString ThemeManager::borderColor() const { return m_darkTheme ? "#304356" : "#c2d0e0"; }
QString ThemeManager::accentColor() const { return m_darkTheme ? "#3ca6ff" : "#0060cc"; }
QString ThemeManager::accentMuted() const { return m_darkTheme ? "#17344f" : "#d6e7fb"; }
QString ThemeManager::dangerColor() const { return m_darkTheme ? "#ff6b6b" : "#c72e2e"; }
QString ThemeManager::warningColor() const { return m_darkTheme ? "#f6b73c" : "#b87700"; }
QString ThemeManager::successColor() const { return m_darkTheme ? "#34cf7a" : "#2c8e4f"; }
QString ThemeManager::controlBg() const { return m_darkTheme ? "#213140" : "#e6eef9"; }
QString ThemeManager::controlBgHover() const { return m_darkTheme ? "#294156" : "#d7e5f7"; }
QString ThemeManager::controlText() const { return m_darkTheme ? "#eef5ff" : "#0f2740"; }
QString ThemeManager::inputBg() const { return m_darkTheme ? "#13212e" : "#ffffff"; }
QString ThemeManager::inputText() const { return m_darkTheme ? "#eef5ff" : "#0f2740"; }
QString ThemeManager::inputPlaceholder() const { return m_darkTheme ? "#89a0b6" : "#738aa4"; }
