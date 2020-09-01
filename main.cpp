#include <QCoreApplication>
#include <QFile>
#include <QString>
#include <QDataStream>
#include <QTextStream>
#include <iostream>
#include <stdlib.h>
#include <time.h>

#include "cryptprocessor.h"
#include "gost28147_89.h"

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    QTextStream cout(stdout);
    QTextStream cin(stdin);

    //---General---

    cout<<"Fragment General launched" << endl;

    CryptProcessor *crProc =new CryptProcessor();
    Gost28147 *gost =new Gost28147();

    QString name_original_file = "C:/Users/Mikhail/Desktop/1488/test_original.bin";
    QString name_file_output_encrypted = "C:/Users/Mikhail/Desktop/1488/test_encrypted.bin";
    QString name_file_output_decrypted = "C:/Users/Mikhail/Desktop/1488/test_decrypted.bin";

    crProc->set_hash("123456");
    QString hashString = crProc->get_hash();
    QByteArray hashByte;
    hashByte.append(hashString);
    cout<<"Fragment General completed" << endl;

    //---Initial actions---

    cout<<"Fragment Initial actions launched" << endl;

    QString console_read;
    QString flag="1";

    QByteArray original_text_array="Developing embedded devices with a cross-platform development\nframework not only saves development cost and time, but also streamlines your\nworkflow and gives you a solid foundation for future innovations.";

    QFile original_file(name_original_file);
    original_file.open(QIODevice::WriteOnly);
    original_file.write(original_text_array);
    original_file.close();
    cout<<"Fragment Initial actions completed" << endl;


    //-------------------------------------------(test)

    cout<< endl;
    cout<<"original text:" << endl;
    QByteArray test;
    original_file.open(QIODevice::ReadOnly);

    QByteArray textFilOriginalTest = original_file.readAll();

    cout << textFilOriginalTest << endl;
    cout<< endl;
    //-------------------------------------------(test end)


    //---Encrypted---

    cout << "Run the Encrypted snippet? (1 or 0)" << endl;
    cin>>console_read;
    if(console_read=="1")
    {
        cout<<"Fragment Encrypted launched" << endl;

        gost->EncryptedFile(name_original_file, hashByte);
        QFile file_output_encrypted(name_file_output_encrypted);
        file_output_encrypted.open(QIODevice::WriteOnly);
        gost->output_file.open(QIODevice::ReadOnly);

        QByteArray fileContentsEncrypted = gost->output_file.readAll();
        file_output_encrypted.write(fileContentsEncrypted);

        file_output_encrypted.close();
        gost->output_file.close();

        console_read="0";
        cout<<"Fragment Encrypted completed" << endl;

        //-------------------------------------------(test)
        cout<< endl;
        cout<<"Encrypted text:" << endl;
        QFile encrypted_file(name_file_output_encrypted);
        encrypted_file.open(QIODevice::ReadOnly);

        QByteArray textFilEncrypted = encrypted_file.readAll();

        cout << textFilEncrypted << endl;
        encrypted_file.close();
        cout<< endl;

        //-------------------------------------------(test end)
    }


    //---Decrypted---

    cout<<"Run the Decrypted snippet? (1 or 0)" << endl;
    cin>>console_read;//console_read=cin.readLine();
    if(console_read=="1")
    {
        cout<<"Fragment Decrypted launched\n" << endl;
        gost->DecryptedFile(name_file_output_encrypted, hashByte);
        QFile file_output_decrypted(name_file_output_decrypted);
        file_output_decrypted.open(QIODevice::WriteOnly);
        gost->output_file.open(QIODevice::ReadOnly);

        QByteArray fileContentsDecrypted = gost->output_file.readAll();
        file_output_decrypted.write(fileContentsDecrypted);

        file_output_decrypted.close();
        gost->output_file.close();
        cout<<"Fragment Decrypted completed\n" << endl;


        //-------------------------------------------(test)
        cout<< endl;
        cout<<"Decrypted text:" << endl;
        QFile decrypted_file(name_file_output_decrypted);
        decrypted_file.open(QIODevice::ReadOnly);

        QByteArray textFilDecrypted = decrypted_file.readAll();

        cout << textFilDecrypted << endl;
        decrypted_file.close();
        cout<< endl;
        //-------------------------------------------(test end)

     }
     return a.exec();

}
