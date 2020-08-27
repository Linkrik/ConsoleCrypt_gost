#include "cryptprocessor.h"
#include <string>
#include "QString"
#include "QCryptographicHash"

CryptProcessor::CryptProcessor()
{

}

void CryptProcessor::set_hash(QString pin)
{
    QByteArray pinUtf = pin.toUtf8();
    this->hash = QCryptographicHash::hash(pinUtf, QCryptographicHash::Sha256).toHex();
}

void CryptProcessor::ser_pin(QString pin)
{
    this->pinCode = pin;
}

QString CryptProcessor::get_hash()
{
    return this->hash;
}
