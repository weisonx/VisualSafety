#pragma once

#include <QObject>
#include <QString>

class EmojiIcons final : public QObject
{
    Q_OBJECT
    Q_PROPERTY(QString dashboard READ dashboard CONSTANT)
    Q_PROPERTY(QString permission READ permission CONSTANT)
    Q_PROPERTY(QString credential READ credential CONSTANT)
    Q_PROPERTY(QString port READ port CONSTANT)
    Q_PROPERTY(QString network READ network CONSTANT)
    Q_PROPERTY(QString alert READ alert CONSTANT)
    Q_PROPERTY(QString log READ log CONSTANT)
    Q_PROPERTY(QString app READ app CONSTANT)
    Q_PROPERTY(QString power READ power CONSTANT)
    Q_PROPERTY(QString restart READ restart CONSTANT)
    Q_PROPERTY(QString block READ block CONSTANT)
    Q_PROPERTY(QString kill READ kill CONSTANT)
    Q_PROPERTY(QString theme READ theme CONSTANT)
    Q_PROPERTY(QString firewall READ firewall CONSTANT)
    Q_PROPERTY(QString traffic READ traffic CONSTANT)
    Q_PROPERTY(QString mail READ mail CONSTANT)
    Q_PROPERTY(QString sms READ sms CONSTANT)
    Q_PROPERTY(QString desktop READ desktop CONSTANT)
    Q_PROPERTY(QString safe READ safe CONSTANT)
    Q_PROPERTY(QString risk READ risk CONSTANT)
    Q_PROPERTY(QString refresh READ refresh CONSTANT)
    Q_PROPERTY(QString search READ search CONSTANT)
    Q_PROPERTY(QString warning READ warning CONSTANT)

public:
    explicit EmojiIcons(QObject *parent = nullptr);

    QString dashboard() const;
    QString permission() const;
    QString credential() const;
    QString port() const;
    QString network() const;
    QString alert() const;
    QString log() const;
    QString app() const;
    QString power() const;
    QString restart() const;
    QString block() const;
    QString kill() const;
    QString theme() const;
    QString firewall() const;
    QString traffic() const;
    QString mail() const;
    QString sms() const;
    QString desktop() const;
    QString safe() const;
    QString risk() const;
    QString refresh() const;
    QString search() const;
    QString warning() const;
};

