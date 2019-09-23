# rm encode
# rm decode
# rm videoout.mp4
# rm pictureout.jpg
# rm videoout2.mp4
# rm pictureout2.jpg
# g++ -Wall -Werror -o encode encode.cpp
# g++ -Wall -Werror -o decode decode.cpp
# ./encode
# ./decode
g++ -Wall -Werror -o RSA RSA.cpp -ldl -lssl -lcrypto
./RSA