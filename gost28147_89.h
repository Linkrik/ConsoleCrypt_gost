#ifndef GOST28147_89_H
#define GOST28147_89_H

#include <QObject>
#include <QFile>
#include <QTemporaryFile>
#include <QBuffer>
#include <QByteArray>

#define LSHIFT_nBIT(x, L, N) (((x << L) | (x >> (-L & (N - 1)))) & (((qint64)1 << N) - 1))
#define BUFF_SIZE 1024

enum Mode
{
	MODE_encrypted = 1,
    MODE_decrypted = 2
};

class Gost28147
{
public:

    QByteArray dataOutput;

    void EncryptedFile(QString input_file_name, QByteArray hash);
    void DecryptedFile(QString input_file_name, QByteArray hash);
    QBuffer output_file; //сохраняет рассшифрованный файл //Создаётся временный файл //QTemporaryFile
private:

    void CryptFeistelCipher(Mode mode, quint32 * block32b_1, quint32 * block32b_2, quint32 * keys32b);
    void CryptRoundOfFeistelCipher(quint32 * block32b_1, quint32 * block32b_2, quint32 * keys32b, quint8 round);

    quint32 CryptSubstitutionTable(quint32 block32b, quint8 sbox_row);
    void CryptSubstitutionTableBy4bits(quint8 * blocks4b, quint8 sbox_row);

    void CryptSplit256bitsTo32bits(quint8 * key256b, quint32 * keys32b); //void CryptSplit256bitsTo32bits(qint8 * key256b, qint32 * keys32b);
    void CryptSplit64bitsTo32bits(quint64 block64b, quint32 * block32b_1, quint32 * block32b_2);
    void CryptSplit64bitsTo8bits(quint64 block64b, quint8 * blocks8b);
    void CryptSplit32bitsTo8bits(quint32 block32b, quint8 * blocks8b);

    quint64 CryptJoin32bitsTo64bits(quint32 block32b_1, quint32 block32b_2);
    quint64 CryptJoin8bitsTo64bits(quint8 * blocks8b);
    quint32 CryptJoin4bitsTo32bits(quint8 * blocks4b);

    quint8 sercet_key[32];
	const quint8 Sbox[8][16] =
    {
        {0xF, 0xC, 0x2, 0xA, 0x6, 0x4, 0x5, 0x0, 0x7, 0x9, 0xE, 0xD, 0x1, 0xB, 0x8, 0x3},
        {0xB, 0x6, 0x3, 0x4, 0xC, 0xF, 0xE, 0x2, 0x7, 0xD, 0x8, 0x0, 0x5, 0xA, 0x9, 0x1},
        {0x1, 0xC, 0xB, 0x0, 0xF, 0xE, 0x6, 0x5, 0xA, 0xD, 0x4, 0x8, 0x9, 0x3, 0x7, 0x2},
        {0x1, 0x5, 0xE, 0xC, 0xA, 0x7, 0x0, 0xD, 0x6, 0x2, 0xB, 0x4, 0x9, 0x3, 0xF, 0x8},
        {0x0, 0xC, 0x8, 0x9, 0xD, 0x2, 0xA, 0xB, 0x7, 0x3, 0x6, 0x5, 0x4, 0xE, 0xF, 0x1},
        {0x8, 0x0, 0xF, 0x3, 0x2, 0x5, 0xE, 0xB, 0x1, 0xA, 0x4, 0x7, 0xC, 0x9, 0xD, 0x6},
        {0x3, 0x0, 0x6, 0xF, 0x1, 0xE, 0x9, 0x2, 0xD, 0x8, 0xC, 0x4, 0xB, 0xA, 0x5, 0x7},
        {0x1, 0xA, 0x6, 0x8, 0xF, 0xB, 0x0, 0x4, 0xC, 0x3, 0x5, 0x9, 0x7, 0xD, 0x2, 0xE},
    };
	

};
#endif // GOST28147_89_H
