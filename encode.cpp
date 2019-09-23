#include <stdio.h>
#include <iostream>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
using namespace std;

// #define FILEIN "videoin.mp4"
// #define FILEOUT "videoout.mp4"
// #define FILEIN "picturein.jpg"
// #define FILEOUT "pictureout.jpg"
#define FILEIN "textin.txt"
#define FILEOUT "textout.txt"
#define NUM_ALPHA 1000
#define FIRST_READ (100)

FILE * f1 = fopen(FILEIN, "rb");
FILE * f2 = fopen(FILEOUT, "wb");
unsigned char buffer[NUM_ALPHA + 5];
int num;
/**********************************/
// RSA config
 char publicKey[]="-----BEGIN PUBLIC KEY-----\n"\
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy8Dbv8prpJ/0kKhlGeJY\n"\
"ozo2t60EG8L0561g13R29LvMR5hyvGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+\n"\
"vw1HocOAZtWK0z3r26uA8kQYOKX9Qt/DbCdvsF9wF8gRK0ptx9M6R13NvBxvVQAp\n"\
"fc9jB9nTzphOgM4JiEYvlV8FLhg9yZovMYd6Wwf3aoXK891VQxTr/kQYoq1Yp+68\n"\
"i6T4nNq7NWC+UNVjQHxNQMQMzU6lWCX8zyg3yH88OAQkUXIXKfQ+NkvYQ1cxaMoV\n"\
"PpY72+eVthKzpMeyHkBn7ciumk5qgLTEJAfWZpe4f4eFZj/Rc8Y8Jj2IS5kVPjUy\n"\
"wQIDAQAB\n"\
"-----END PUBLIC KEY-----\n";
int padding = RSA_PKCS1_PADDING;
unsigned char  encrypted[4098]={};
/************************/
// public encrypt RSA
RSA * createRSA(unsigned char * key,int publicc)
{
    RSA *rsa= NULL;
    BIO *keybio ;
    keybio = BIO_new_mem_buf(key, -1);
    if (keybio==NULL)
    {
        printf( "Failed to create key BIO");
        return 0;
    }
    if(publicc)
    {
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
    }
    else
    {
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
    }
    if(rsa == NULL)
    {
        printf( "Failed to create RSA");
    }

    return rsa;
}

int public_encrypt(unsigned char * data, int data_len, unsigned char * key, unsigned char *encrypted)
{
    RSA * rsa = createRSA(key, 1);
    int result = RSA_public_encrypt(data_len, data, encrypted, rsa, padding);
    return result;
}

/****************************/
int main(){
    printf("\n\n\n----------------Begin Encript---------\n");
    int sumReadByte = 0;     
    int num = 0;
    memset(buffer, 0, NUM_ALPHA);

    num = fread(buffer, sizeof(char), FIRST_READ, f1);
    if(num) { // read succecc
        printf("read first %d byte\n", num);
    } else {
        printf("read first false \n");        
    }

    sumReadByte += num;
    buffer[FIRST_READ + 1] = '\0';
    int encrypted_length = public_encrypt(buffer, strlen((char*) buffer), (unsigned char*) publicKey, encrypted);

    if(encrypted_length == -1)
    {
        printf("Public Encrypt failed \n");
    } else {        
        printf("first read length = %d\ndata read = \n", num);
        for (int i = 0; i < num; i++){
            printf("%02x %c", buffer[i], (i % 20 == 0 && i != 0) ? '\n' : '\t');
        }
        printf("\n");
        
        printf("encrypted_length = %d\ndata encrypt = \n", encrypted_length);
        for (int i = 0; i < encrypted_length; i++){
            printf("%02x %c", encrypted[i], (i % 20 == 0 && i != 0) ? '\n' : '\t');
            fwrite(encrypted, sizeof(char), encrypted_length, f2); 
        }
        printf("\n");
    }

    while(1){
        memset(buffer, 0, sizeof(buffer));
        num = fread(buffer, sizeof( char ), NUM_ALPHA, f1 );
        if ( num ) {  /* fread success */
            sumReadByte += num;
            fwrite(buffer, sizeof(char), num, f2);  
        } else {  /* fread failed */
            if ( ferror(f1) )    /* possibility 1 */
                perror( "Error reading myfile" );
            else if ( feof(f1)) {  /* possibility 2 */
                perror( "EOF found" );
                printf("read all %d bytes in %s\n", sumReadByte, FILEIN);
            }
            break;
        }
    }
    fclose(f1);
    fclose(f2);
    return 0;
}