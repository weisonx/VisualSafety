#include "emojiicons.h"

EmojiIcons::EmojiIcons(QObject *parent)
    : QObject(parent)
{
}

QString EmojiIcons::dashboard() const { return QString::fromUtf8("\xF0\x9F\x9B\xA1\xEF\xB8\x8F"); }
QString EmojiIcons::permission() const { return QString::fromUtf8("\xF0\x9F\x94\x90"); }
QString EmojiIcons::credential() const { return QString::fromUtf8("\xF0\x9F\x97\x9D\xEF\xB8\x8F"); }
QString EmojiIcons::port() const { return QString::fromUtf8("\xF0\x9F\x94\x8C"); }
QString EmojiIcons::network() const { return QString::fromUtf8("\xF0\x9F\x8C\x90"); }
QString EmojiIcons::alert() const { return QString::fromUtf8("\xF0\x9F\x9A\xA8"); }
QString EmojiIcons::log() const { return QString::fromUtf8("\xF0\x9F\x93\x9D"); }
QString EmojiIcons::app() const { return QString::fromUtf8("\xF0\x9F\xA7\xA9"); }
QString EmojiIcons::power() const { return QString::fromUtf8("\xE2\x8F\xBB"); }
QString EmojiIcons::restart() const { return QString::fromUtf8("\xF0\x9F\x94\x84"); }
QString EmojiIcons::block() const { return QString::fromUtf8("\xE2\x9B\x94"); }
QString EmojiIcons::kill() const { return QString::fromUtf8("\xE2\x9C\x82\xEF\xB8\x8F"); }
QString EmojiIcons::theme() const { return QString::fromUtf8("\xF0\x9F\x8C\x97"); }
QString EmojiIcons::firewall() const { return QString::fromUtf8("\xF0\x9F\xA7\xB1"); }
QString EmojiIcons::traffic() const { return QString::fromUtf8("\xF0\x9F\x93\x8A"); }
QString EmojiIcons::mail() const { return QString::fromUtf8("\xF0\x9F\x93\xA7"); }
QString EmojiIcons::sms() const { return QString::fromUtf8("\xF0\x9F\x93\xB2"); }
QString EmojiIcons::desktop() const { return QString::fromUtf8("\xF0\x9F\x96\xA5\xEF\xB8\x8F"); }
QString EmojiIcons::safe() const { return QString::fromUtf8("\xE2\x9C\x85"); }
QString EmojiIcons::risk() const { return QString::fromUtf8("\xE2\x98\xA0\xEF\xB8\x8F"); }
QString EmojiIcons::refresh() const { return QString::fromUtf8("\xF0\x9F\x94\x83"); }
QString EmojiIcons::search() const { return QString::fromUtf8("\xF0\x9F\x94\x8E"); }
QString EmojiIcons::warning() const { return QString::fromUtf8("\xE2\x9A\xA0\xEF\xB8\x8F"); }

