#include <iostream>
std::string base64_encode(const std::string &);

int char2int(char input) {
  if(input >= '0' && input <= '9')
    return input - '0';
  if(input >= 'A' && input <= 'F')
    return input - 'A' + 10;
  if(input >= 'a' && input <= 'f')
    return input - 'a' + 10;
  throw;
}

void hex2bin(const char* src, char* target) {
  while(*src && src[1]) {
    *(target++) = char2int(*src)*16 + char2int(src[1]);
    src += 2;
  }
}

int main() {

/*
drive.google.com/open?id=0B0KFXc-NLCUcbTBHWFMtX0NiYjg
webbtc.com/tx/288bcaaa05389922d5da1ee0e6d2d08e72770754e0c830adba50e0daa95efd48
*/
#include "tx390580hex.txt"

   for(int i=0; i<1182; ++i) {
      char tmp[32];
      hex2bin( (leaves390580[i]).data() , tmp );
      const std::string r = base64_encode(std::string(tmp,tmp+32));
      std::cout << '"' << r << "\",\n";
   }

   char t[223];
   hex2bin(txin288bcaaa.data(), t);
   const std::string r = base64_encode(std::string(t,t+223));
   std::cout << "\n\"" << r << "\";\n";

   return 0;
}
