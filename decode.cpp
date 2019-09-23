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

#define uc unsigned char
// #define FILEIN "videoin.mp4"
// #define FILEOUT "videoout.mp4"
// #define FILEIN "pictureout.jpg"
// #define FILEOUT "pictureout2.jpg"
#define FILEIN "textout.txt"
#define FILEOUT "textout2.txt"
#define NUM_ALPHA 1000
#define FIRST_READ (256)


FILE * f1 = fopen(FILEIN, "rb");
FILE * f2 = fopen(FILEOUT, "wb");
uc buffer[NUM_ALPHA + 1];
int num;
/*****************RSA config*****************/
unsigned char decrypted[4098]={};
int padding = RSA_PKCS1_PADDING;
unsigned char privateKey[]="-----BEGIN RSA PRIVATE KEY-----\n"\
"MIIEowIBAAKCAQEAy8Dbv8prpJ/0kKhlGeJYozo2t60EG8L0561g13R29LvMR5hy\n"\
"vGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+vw1HocOAZtWK0z3r26uA8kQYOKX9\n"\
"Qt/DbCdvsF9wF8gRK0ptx9M6R13NvBxvVQApfc9jB9nTzphOgM4JiEYvlV8FLhg9\n"\
"yZovMYd6Wwf3aoXK891VQxTr/kQYoq1Yp+68i6T4nNq7NWC+UNVjQHxNQMQMzU6l\n"\
"WCX8zyg3yH88OAQkUXIXKfQ+NkvYQ1cxaMoVPpY72+eVthKzpMeyHkBn7ciumk5q\n"\
"gLTEJAfWZpe4f4eFZj/Rc8Y8Jj2IS5kVPjUywQIDAQABAoIBADhg1u1Mv1hAAlX8\n"\
"omz1Gn2f4AAW2aos2cM5UDCNw1SYmj+9SRIkaxjRsE/C4o9sw1oxrg1/z6kajV0e\n"\
"N/t008FdlVKHXAIYWF93JMoVvIpMmT8jft6AN/y3NMpivgt2inmmEJZYNioFJKZG\n"\
"X+/vKYvsVISZm2fw8NfnKvAQK55yu+GRWBZGOeS9K+LbYvOwcrjKhHz66m4bedKd\n"\
"gVAix6NE5iwmjNXktSQlJMCjbtdNXg/xo1/G4kG2p/MO1HLcKfe1N5FgBiXj3Qjl\n"\
"vgvjJZkh1as2KTgaPOBqZaP03738VnYg23ISyvfT/teArVGtxrmFP7939EvJFKpF\n"\
"1wTxuDkCgYEA7t0DR37zt+dEJy+5vm7zSmN97VenwQJFWMiulkHGa0yU3lLasxxu\n"\
"m0oUtndIjenIvSx6t3Y+agK2F3EPbb0AZ5wZ1p1IXs4vktgeQwSSBdqcM8LZFDvZ\n"\
"uPboQnJoRdIkd62XnP5ekIEIBAfOp8v2wFpSfE7nNH2u4CpAXNSF9HsCgYEA2l8D\n"\
"JrDE5m9Kkn+J4l+AdGfeBL1igPF3DnuPoV67BpgiaAgI4h25UJzXiDKKoa706S0D\n"\
"4XB74zOLX11MaGPMIdhlG+SgeQfNoC5lE4ZWXNyESJH1SVgRGT9nBC2vtL6bxCVV\n"\
"WBkTeC5D6c/QXcai6yw6OYyNNdp0uznKURe1xvMCgYBVYYcEjWqMuAvyferFGV+5\n"\
"nWqr5gM+yJMFM2bEqupD/HHSLoeiMm2O8KIKvwSeRYzNohKTdZ7FwgZYxr8fGMoG\n"\
"PxQ1VK9DxCvZL4tRpVaU5Rmknud9hg9DQG6xIbgIDR+f79sb8QjYWmcFGc1SyWOA\n"\
"SkjlykZ2yt4xnqi3BfiD9QKBgGqLgRYXmXp1QoVIBRaWUi55nzHg1XbkWZqPXvz1\n"\
"I3uMLv1jLjJlHk3euKqTPmC05HoApKwSHeA0/gOBmg404xyAYJTDcCidTg6hlF96\n"\
"ZBja3xApZuxqM62F6dV4FQqzFX0WWhWp5n301N33r0qR6FumMKJzmVJ1TA8tmzEF\n"\
"yINRAoGBAJqioYs8rK6eXzA8ywYLjqTLu/yQSLBn/4ta36K8DyCoLNlNxSuox+A5\n"\
"w6z2vEfRVQDq4Hm4vBzjdi3QfYLNkTiTqLcvgWZ+eX44ogXtdTDO7c+GeMKWz4XX\n"\
"uJSUVL5+CVjKLjZEJ6Qc2WZLl94xSwL71E41H4YciVnSCQxVc4Jw\n"\
"-----END RSA PRIVATE KEY-----\n";

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
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa,NULL, NULL);
    }
    else
    {
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa,NULL, NULL);
    }
    if(rsa == NULL)
    {
        printf( "Failed to create RSA");
    }

    return rsa;
}

int private_decrypt(unsigned char * enc_data, int data_len, unsigned char * key, unsigned char *decrypted)
{
    RSA * rsa = createRSA(key, 0);
    int  result = RSA_private_decrypt(data_len, enc_data, decrypted, rsa, padding);
    return result;
}

/*********************************/
int main(){
    printf("\n\n\n----------------Begin Decript---------\n");
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

    int decript_length = private_decrypt(buffer, FIRST_READ, privateKey, decrypted);

    if (decript_length == -1){
        printf("flase Decription\n");
    } else {
        printf("first read length = %d\ndata read = \n", num);
        for (int i = 0; i < num; i++){
            printf("%02x %c", buffer[i], (i % 20 == 0 && i != 0) ? '\n' : '\t');
        }
        printf("\n");
        
        printf("decript_length = %d\ndata decrypt = \n", decript_length);
        for (int i = 0; i < decript_length; i++){
            printf("%02x %c", decrypted[i], (i % 20 == 0 && i != 0) ? '\n' : '\t');
            fwrite(decrypted, sizeof(char), decript_length, f2); 
        }
        printf("\n");
    }
    while(1){
        memset(buffer, 0, sizeof(buffer));
        num = fread(buffer, sizeof(uc), NUM_ALPHA, f1 );
        if ( num ) {  /* fread success */
            fwrite(buffer, sizeof(uc), num, f2);
            sumReadByte += num;  
        } else {  /* fread failed */
            if ( ferror(f1) )    /* possibility 1 */
                perror( "Error reading myfile" );
            else if ( feof(f1)){  /* possibility 2 */
                perror( "EOF found");
                printf("read all %d bytes in %s\n", sumReadByte, FILEIN);
            }
            break;
        }
    }
    fclose(f1);
    fclose(f2);
    return 0;
}