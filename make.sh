rm encode
rm decode
rm videoout.mp4
rm pictureout.jpg
#rm textout.txt
rm videoout2.mp4
rm pictureout2.jpg
#rm textout2.txt
g++ -Wall -Werror -o encode encode.cpp -ldl -lssl -lcrypto
g++ -Wall -Werror -o decode decode.cpp -ldl -lssl -lcrypto
./encode
./decode
# g++ -Wall -Werror -o RSA RSA.cpp -ldl -lssl -lcrypto
# ./RSA
