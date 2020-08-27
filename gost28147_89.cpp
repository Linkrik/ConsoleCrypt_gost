#include "gost28147_89.h"
#include<iostream>
#include<fstream>


//---Public:---
void Gost28147::EncryptedFile(QString input_file_name, QByteArray hash)  //hash - key //QFile input_file
{
    QFile input_file(input_file_name);
    QFile test("C:/Users/Mikhail/Desktop/1488/test.txt");

    //т.к. hash 40 байт, а нам нужно 32
    for (qint8 i = 0; i < 32; i++) // было: for (qint8 i = 0; i < 8; i++) //i < 32
    this->sercet_key[i] = hash[i];
	
    test.open(QIODevice::WriteOnly);
    //-
    input_file.open(QIODevice::ReadOnly | QFile::Text); //открываем наш файл только для чтения данных
    this->output_file.open(QIODevice::WriteOnly); //открываем наш буфер только для записи данных //encrypted_file поле  //QIODevice::WriteOnly


    quint32 length_file_one = input_file.size(); // узнаем размер файла
    quint32 length_file_two = length_file_one % 8 == 0 ? length_file_one : length_file_one + (8 - (length_file_one % 8)); //дополняем размер файла если он не кратен 8


    quint32 N1, N2, keys32b[8];
    this->CryptSplit256bitsTo32bits(this->sercet_key, keys32b);//sercet_key - hash  //переписать


    quint32 counter=0;

    for (quint32 i = 0; i < length_file_two; i += 8)
    {
        quint8 read_block_file_8b[8];    //crypt_block8b
        quint8 wriate_block_file_8b[8];  //encrypt_block8b
        char read_byte;
        char wriat_byte;

        for (qint32 j = 0; j < 8; j++)
        {
            input_file.read(&read_byte, sizeof (char));
            read_block_file_8b[j] = read_byte; //[i]
            //test.write(&read_byte, sizeof (char));
            //counter++;
        }

        //---


        (
            this->CryptJoin8bitsTo64bits(read_block_file_8b), //+i
            &N1,
            &N2
        );

        this->CryptFeistelCipher(Mode::MODE_encrypted, &N1, &N2, keys32b);
        this->CryptSplit64bitsTo8bits
        (
          this->CryptJoin32bitsTo64bits(N1, N2),
          wriate_block_file_8b
        );

        for (qint32 j = 0; j < 8; j++)
        {
            wriat_byte = wriate_block_file_8b[j]; //[i]
            this->output_file.write(&wriat_byte, sizeof (char));
            this->dataOutput[counter] = wriat_byte;
        }


     }

    test.close();
    input_file.close();
    output_file.close();
}



void Gost28147::DecryptedFile(QString input_file_name, QByteArray hash)  //hash - key //QFile input_file
{
    QFile input_file(input_file_name);

    for (qint8 i = 0; i < 8; i++) // было: for (qint8 i = 0; i < 8; i++)
    sercet_key[i] = hash[i];


    input_file.open(QIODevice::ReadOnly | QFile::Text); //открываем наш файл только для чтения данных
    this->output_file.open(QIODevice::WriteOnly); //открываем наш файл только для записи данных //encrypted_file поле  //QIODevice::WriteOnly


    qint32 length_file = input_file.size(); // узнаем размер файла
    length_file = length_file % 8 == 0 ? length_file : length_file + (8 - (length_file % 8)); //дополняем размер файла если он не кратен 8


    quint32 N1, N2, keys32b[8];
    this->CryptSplit256bitsTo32bits(this->sercet_key, keys32b);//sercet_key - hash


    for (qint32 i = 0; i < length_file; i += 8)
    {
        quint8 read_block_file_8b[8];    //crypt_block8b
        quint8 wriate_block_file_8b[8];  //encrypt_block8b
        char read_byte;
        char wriat_byte;

        for (qint32 j = 0; j < 8; j++)
        {
            input_file.read(&read_byte, sizeof (char));
            read_block_file_8b[j] = read_byte; //[i]
        }

        //---
        this->CryptSplit64bitsTo32bits
        (
            this->CryptJoin8bitsTo64bits(read_block_file_8b),//+i
            &N1,
            &N2
        );

        this->CryptFeistelCipher(Mode::MODE_decrypted, &N1, &N2, keys32b);
        this->CryptSplit64bitsTo8bits
        (
          this->CryptJoin32bitsTo64bits(N1, N2),
          wriate_block_file_8b
        );

        for (qint32 j = 0; j < 8; j++)
        {
            wriat_byte = wriate_block_file_8b[j]; //[i]
            this->output_file.write(&wriat_byte, sizeof (char));
        }
     }
    input_file.close();
    output_file.close();
}




//---Private:---
quint64 Gost28147::CryptJoin8bitsTo64bits(quint8 * blocks8b)
{
    quint64 block64b;
    for (quint8 *p = blocks8b; p < blocks8b + 8; ++p)
    {
        block64b = (block64b << 8) | *p;
    }
    return block64b;
}

void Gost28147::CryptSplit64bitsTo32bits(quint64 block64b, quint32 * block32b_1, quint32 * block32b_2)
{
    *block32b_2 = (quint32)(block64b);
    *block32b_1 = (quint32)(block64b >> 32);
}

//переписать
void Gost28147::CryptSplit256bitsTo32bits(quint8 * key256b, quint32 * keys32b)//функция разбиения 256 бит на 8 блоков по 32 бита
{
    quint8 *p8 = key256b;
    for (quint32 *p32 = keys32b; p32 < keys32b + 8; ++p32)
    {
        for (quint8 i = 0; i < 4; ++i)
        {
            *p32 = (*p32 << 8) | *(p8 + i);
        }
        p8 += 4;
    }
}



void Gost28147::CryptFeistelCipher(Mode mode, quint32 * block32b_1, quint32 * block32b_2, quint32 * keys32b)
{
    switch (mode)
    {
        case MODE_encrypted:
        {
            for (quint8 round = 0; round < 24; ++round)
                this->CryptRoundOfFeistelCipher(block32b_1, block32b_2, keys32b, round);

            for (quint8 round = 31; round >= 24; --round)
                this->CryptRoundOfFeistelCipher(block32b_1, block32b_2, keys32b, round);
            break;
        }

        case MODE_decrypted:
        {
            for (quint8 round = 0; round < 8; ++round)
                this->CryptRoundOfFeistelCipher(block32b_1, block32b_2, keys32b, round);

            for (quint8 round = 31; round >= 8; --round)
                this->CryptRoundOfFeistelCipher(block32b_1, block32b_2, keys32b, round);
            break;
        }
    }
}

void Gost28147::CryptRoundOfFeistelCipher(quint32 * block32b_1, quint32 * block32b_2, quint32 * keys32b, quint8 round)
{
    quint32 result_of_iter, temp;

    result_of_iter = (*block32b_1 + keys32b[round % 8]) % UINT32_MAX;
    result_of_iter = this->CryptSubstitutionTable(result_of_iter, round % 8);
    result_of_iter = (quint32)LSHIFT_nBIT(result_of_iter, 11, 32);

    temp = *block32b_1;
    *block32b_1 = result_of_iter ^ *block32b_2;
    *block32b_2 = temp;
}

quint32 Gost28147::CryptSubstitutionTable(quint32 block32b, quint8 sbox_row)
{
    quint8 blocks4bits[4];
    this->CryptSplit32bitsTo8bits(block32b, blocks4bits);
    this->CryptSubstitutionTableBy4bits(blocks4bits, sbox_row);
    return this->CryptJoin4bitsTo32bits(blocks4bits);
}

void Gost28147::CryptSplit32bitsTo8bits(quint32 block32b, quint8 * blocks8b)
{
    for (quint8 i = 0; i < 4; ++i)
    {
        blocks8b[i] = (quint8)(block32b >> (24 - (i * 8)));
    }
}

void Gost28147::CryptSubstitutionTableBy4bits(quint8 * blocks4b, quint8 sbox_row)
{
    quint8 block4b_1, block4b_2;
    for (quint8 i = 0; i < 4; ++i)
    {
        block4b_1 = Sbox[sbox_row][blocks4b[i] & 0x0F];
        block4b_2 = Sbox[sbox_row][blocks4b[i] >> 4];
        blocks4b[i] = block4b_2;
        blocks4b[i] = (blocks4b[i] << 4) | block4b_1;
    }
}

quint32 Gost28147::CryptJoin4bitsTo32bits(quint8 * blocks4b)
{
    quint32 block32b;
    for (quint8 i = 0; i < 4; ++i)
    {
        block32b = (block32b << 8) | blocks4b[i];
    }
    return block32b;
}

void Gost28147::CryptSplit64bitsTo8bits(quint64 block64b, quint8 * blocks8b)
{
    for (size_t i = 0; i < 8; ++i)
    {
        blocks8b[i] = (quint8)(block64b >> ((7 - i) * 8));
    }
}


quint64 Gost28147::CryptJoin32bitsTo64bits(quint32 block32b_1, quint32 block32b_2)
{
    quint64 block64b;
    block64b = block32b_2;
    block64b = (block64b << 32) | block32b_1;
    return block64b;
}
