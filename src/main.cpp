#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QQmlContext>

#include "core/securitycontroller.h"
#include "core/thememanager.h"
#include "icons/emojiicons.h"

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
    return app.exec();
}
