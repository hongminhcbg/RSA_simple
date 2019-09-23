#include <stdio.h>
#include <iostream>
#include <string.h>
#include <stdint.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
using namespace std;

#define uc unsigned char
#define FILEIN "videoout.mp4"
#define FILEOUT "videoout2.mp4"
// #define FILEIN "pictureout.jpg"
// #define FILEOUT "pictureout2.jpg"
// #define FILEIN "textout.txt"
// #define FILEOUT "textout2.txt"
#define NUM_ALPHA 1000
#define FIRST_READ (256)
#define MAX_LEN_B64 (256)

FILE * f1 = fopen(FILEIN, "rb");
FILE * f2 = fopen(FILEOUT, "wb");
uc buffer[NUM_ALPHA + 1];
int num;
static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '-', '_'};
static char *decoding_table = NULL;

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
// decode base 64 funtion
void build_decoding_table() {
    decoding_table = (char*) malloc(256);

    for (int i = 0; i < 64; i++){
        decoding_table[(unsigned char) encoding_table[i]] = i;
    }    
}

unsigned char *base64_decode(unsigned char *data, int inputLength, int *output_length) {
    if (decoding_table == NULL) build_decoding_table();
    *output_length = inputLength / 4 * 3;
    if (data[inputLength - 1] == '=') (*output_length)--;
    if (data[inputLength - 2] == '=') (*output_length)--;
    unsigned char *decoded_data = (unsigned char*) malloc(*output_length);
    if (decoded_data == NULL) return NULL;
    for (int i = 0, j = 0; i < inputLength;) {

        uint32_t sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];

        uint32_t triple = (sextet_a << 3 * 6)
        + (sextet_b << 2 * 6)
        + (sextet_c << 1 * 6)
        + (sextet_d << 0 * 6);

        if (j < *output_length) decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
    }
    //printf("[LHM log %d] end base64_decode\n", __LINE__);

    return decoded_data;
}

int main(){
    printf("\n\n\n----------------Begin Decript---------\n");
    int sumWriteByte = 0;    
    int num = 0;
    memset(buffer, 0, NUM_ALPHA);

    // step 1 read file
    num = fread(buffer, sizeof(char), FIRST_READ, f1);
    if(num == FIRST_READ) { // read succecc
        printf("step1: read first %d byte success\n", num);
    } else {
        printf("step1: read first %d byte false \n", FIRST_READ);
        return 0;        
    }

    // step 2 decode RSA
    int decript_length = private_decrypt(buffer, FIRST_READ, privateKey, decrypted);

    if (decript_length == -1){
        printf("step2: RSA decode flase\n");
    } else {
        printf("step2: RSA decode sucess\ndata read : \n");
        for (int i = 0; i < num; i++){
            printf("%02x %c", buffer[i], (i+1) % 16 == 0 ? '\n' : '\t');
        }
        printf("\n");
        
        printf("decript_length = %d, data decrypt: \n", decript_length);
        for (int i = 0; i < decript_length; i++){
            printf("%c", decrypted[i]);
        }
        printf("\n");
    }

    // step3 encode base 64 decrypted
    unsigned char *b64Decode = (unsigned char*) malloc(MAX_LEN_B64);
    int b64OutLen = 0;
    b64Decode = base64_decode(decrypted, decript_length, &b64OutLen);
    if(b64Decode == NULL){
        printf("step3: decde base 64 false\n");
        return 0;
    } else {
        printf("b64OutLen = %d, data decode base 64:\n", b64OutLen);
        for(int i = 0; i < b64OutLen; i++){
            printf("%02X %c", b64Decode[i], (i + 1) % 16 == 0 ? '\n' : '\t');
        }
        printf("\n");
        fwrite(b64Decode, sizeof(uc), b64OutLen, f2);
        sumWriteByte += b64OutLen;
    }

    while(1){
        memset(buffer, 0, sizeof(buffer));
        num = fread(buffer, sizeof(uc), NUM_ALPHA, f1 );
        if ( num ) {  /* fread success */
            fwrite(buffer, sizeof(uc), num, f2);
            sumWriteByte += num;  
        } else {  /* fread failed */
            if ( ferror(f1) ){    /* possibility 1 */
                perror( "Error reading myfile" );
                printf("step 4: write date to file out error");
            }
            else if ( feof(f1) ){  /* possibility 2 */
                perror( "EOF found");
                printf("wirite all %d bytes to %s\n", sumWriteByte, FILEOUT);
                printf("step 4: write date to file out success\n===============>done Decrypt\n\n");
            }
            break;
        }
    }
    fclose(f1);
    fclose(f2);
    return 0;
}