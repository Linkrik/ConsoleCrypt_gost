#ifndef CRYPTPROCESSOR_H
#define CRYPTPROCESSOR_H
#include <string>
#include "QString"

class CryptProcessor
{
public:
    //получение хеша из pin кода
    void set_hash(QString);
    //cчитывание pin кода
    void ser_pin(QString);
    //
    QString get_hash();
    //
    CryptProcessor();

private:
    //хеш pin кода;
    QString hash;
    QString pinCode;

};

#endif // CRYPTPROCESSOR_H
