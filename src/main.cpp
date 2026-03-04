#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QQuickWindow>
#include <QColor>

#include "core/securitycontroller.h"
#include "core/thememanager.h"
#include "icons/emojiicons.h"

#ifdef Q_OS_WIN
#include <windows.h>
#include <dwmapi.h>
#endif

#ifdef Q_OS_WIN
static void ApplyWindowsTitleBarTheme(QWindow *window, const ThemeManager &theme)
{
    if (!window) {
        return;
    }

    const HWND hwnd = reinterpret_cast<HWND>(window->winId());
    if (!hwnd) {
        return;
    }

    const QColor captionQColor(theme.sidebarBg());
    const QColor textQColor(theme.textPrimary());

    if (!captionQColor.isValid() || !textQColor.isValid()) {
        return;
    }

    const COLORREF captionColor = RGB(captionQColor.red(), captionQColor.green(), captionQColor.blue());
    const COLORREF textColor = RGB(textQColor.red(), textQColor.green(), textQColor.blue());

    const BOOL dark = theme.darkTheme() ? TRUE : FALSE;

    // Not all DWM attributes exist on all Windows versions; ignore failures.
    // Immersive dark mode: 20 (Win10 1809+), 19 (some older SDKs).
    DwmSetWindowAttribute(hwnd, 20, &dark, sizeof(dark));
    DwmSetWindowAttribute(hwnd, 19, &dark, sizeof(dark));

    // Caption/text colors: 35/36 (Win11+). Border: 34.
    DwmSetWindowAttribute(hwnd, 35, &captionColor, sizeof(captionColor));
    DwmSetWindowAttribute(hwnd, 36, &textColor, sizeof(textColor));
    DwmSetWindowAttribute(hwnd, 34, &captionColor, sizeof(captionColor));
}
#endif

int main(int argc, char *argv[])
{
    QGuiApplication app(argc, argv);

    ThemeManager theme;
    SecurityController security;
    EmojiIcons icons;

    QQmlApplicationEngine engine;
    engine.rootContext()->setContextProperty("Theme", &theme);
    engine.rootContext()->setContextProperty("Security", &security);
    engine.rootContext()->setContextProperty("Icons", &icons);

    QObject::connect(
        &engine,
        &QQmlApplicationEngine::objectCreationFailed,
        &app,
        []() { QCoreApplication::exit(-1); },
        Qt::QueuedConnection);

    engine.loadFromModule("VisualSafety", "Main");

#ifdef Q_OS_WIN
    if (!engine.rootObjects().isEmpty()) {
        auto *window = qobject_cast<QQuickWindow *>(engine.rootObjects().constFirst());
        ApplyWindowsTitleBarTheme(window, theme);
        QObject::connect(&theme, &ThemeManager::themeChanged, window, [&theme, window]() {
            ApplyWindowsTitleBarTheme(window, theme);
        });
    }
#endif

    return app.exec();
}
