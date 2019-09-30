#include "decodeLHM.h"
#include <iostream>
#include <string>
using namespace std;
int main(){
    printHelo();
    string s = "videoout.mp4";
    if( decodeLHM(s) ){
        printf("decode success\n");
    } else {
        printf("decode false\n");
    }
}