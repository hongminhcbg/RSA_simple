#include <stdio.h>
#include <iostream>
#include <string.h>
#define uc unsigned char
// #define FILEIN "videoin.mp4"
// #define FILEOUT "videoout.mp4"
#define FILEIN "pictureout.jpg"
#define FILEOUT "pictureout2.jpg"
#define NUM_ALPHA 1000
using namespace std;

FILE * f1 = fopen(FILEIN, "rb");
FILE * f2 = fopen(FILEOUT, "wb");
uc buffer[NUM_ALPHA + 1];
int num;
int main(){
    while(1){
        memset(buffer, 0, sizeof(buffer));
        num = fread(buffer, sizeof( uc ), NUM_ALPHA, f1 );
        if ( num ) {  /* fread success */
            printf( "Number of characters has been read = %i in %s \n", num, FILEIN );
            buffer[0] = ~buffer[0];
            fwrite(buffer, sizeof(uc), num, f2);  
//            fclose( f1 );
        } else {  /* fread failed */
            if ( ferror(f1) )    /* possibility 1 */
                perror( "Error reading myfile" );
            else if ( feof(f1))  /* possibility 2 */
                perror( "EOF found" );
            break;
        }
    }
    fclose(f1);
    fclose(f2);
    return 0;
}