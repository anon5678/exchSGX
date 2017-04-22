#include <openssl/sha.h>
#include <iostream>
#include <iomanip>
#include <cstring>

std::string base64_encode(const std::string &);
std::string base64_decode(const std::string &);

typedef unsigned char arrdigest[SHA256_DIGEST_LENGTH];

void hexdump(const unsigned char* data, int len) {
   std::cout << std::hex;
   for(int i=0; i<len; ++i)
      std::cout << std::setfill('0') << std::setw(2) << (int)data[i];
   std::cout << std::endl;
}

void byte_swap(unsigned char* data, int len) {
        unsigned char tmp[len];
        int c=0;
        while(c<len) {
                tmp[c] = data[len-(c+1)];
                c++;
        }
        c=0;
        while(c<len) {
                data[c] = tmp[c];
                c++;
        }
}

//s1+s2 are the 32+32 bytes input, dst is 32 bytes output
void sha256double(void const* const s1,
                  void const* const s2, void * const dst) {
   SHA256_CTX h1, h2;
   unsigned char tmp[SHA256_DIGEST_LENGTH];
   
   SHA256_Init(&h1);
   //if(NULL != s1)
      SHA256_Update(&h1, (unsigned char*)s1, SHA256_DIGEST_LENGTH);
   //if(NULL != s2)
      SHA256_Update(&h1, (unsigned char*)s2, SHA256_DIGEST_LENGTH);
   SHA256_Final(tmp, &h1);

   SHA256_Init(&h2);
   SHA256_Update(&h2, tmp, SHA256_DIGEST_LENGTH);
   SHA256_Final((unsigned char *)dst, &h2);
}

void recursiveMerk(const arrdigest * level, int size, int path) {
   int k = (size + (size & 1))/2;
   arrdigest * next = new arrdigest[k];

   for(int i=0; i<k; ++i){
      const unsigned char * left_node = level[2*i];
      const unsigned char * right_node =
         ((2*i + 1) == size ? left_node : level[2*i+1]);
      sha256double(left_node, right_node, next[i]);
      if(path == (2*i+1)) {
         std::cout << "L: ";
         hexdump(left_node, SHA256_DIGEST_LENGTH);
         continue;
      }
      if(path == (2*i)) {
         std::cout << "R: ";
         if(left_node != right_node)
            hexdump(right_node, SHA256_DIGEST_LENGTH);
         else
            std::cout << std::endl;
      }
   }
   if (k>1)
      recursiveMerk(next,k,path/2);
   else {
      byte_swap(next[0], SHA256_DIGEST_LENGTH);
      hexdump(next[0], SHA256_DIGEST_LENGTH);
   }
   delete[] next;
}

void merkGenPath(const std::string * leaf_nodes, int size, int index) {
   arrdigest * mTree = new arrdigest[size];

   for(int i=0; i<size; ++i) {
      unsigned char * tmp = mTree[i];
      std::memcpy(tmp, (base64_decode(leaf_nodes[i])).data(), 32);
      //hexdump(tmp, 32);
      byte_swap(tmp, 32);
   }

   if (size>1) recursiveMerk(mTree,size,index);

   delete[] mTree;
}

void merkVerifyPath(const std::string & leaf, const std::string * branch,
   int size) {
   unsigned char tmp[1+SHA256_DIGEST_LENGTH];
   unsigned char curr[SHA256_DIGEST_LENGTH];

   std::memcpy(curr, (base64_decode(leaf)).data(), 32);
   byte_swap(curr, 32);

   for(int i=0; i<size; ++i) {
      if( (branch[i]).empty() ) {
         sha256double(curr, curr, curr);
         continue;
      }
      std::memcpy(tmp, (base64_decode(branch[i])).data(), 33);
      if('L' == tmp[0])
         sha256double(tmp+1, curr, curr);
      else
         sha256double(curr, tmp+1, curr);
   }
   
   byte_swap(curr, 32);
   hexdump(curr, 32);
}

int main() {

#if 0
   //7595609fdc8ab6a480d6db13ca641f59c5ac42153c769d034a30adb8874bacef
   const std::string p1 = "vrOZ+JXMUv97aIzgW0Psm2tYmVNiWXHiAtK+ans2jx4=";
   arrdigest p1r;
   std::memcpy(p1r, (base64_decode(p1)).data(), 32);
   hexdump(p1r, 32);
   byte_swap(p1r, 32);

   const std::string p2 = "giA1MPwp6OQDUh0jbnhS9nyPBoeAwMHorigjkb1Kamw";
   arrdigest p2r;
   std::memcpy(p2r, (base64_decode(p2)).data(), 32);
   hexdump(p2r, 32);
   byte_swap(p2r, 32);

   arrdigest result;
   sha256double(p1r, p2r, result);
   byte_swap(result, SHA256_DIGEST_LENGTH);
   hexdump(result, SHA256_DIGEST_LENGTH);

   const std::string r = base64_encode(std::string(result,result+32));
   std::cout << r << std::endl;
#endif

   //b42be2d0403e5a7336b1f5e2b5c344827177d191b1cbced3565b7ba138d8a83d
   const std::string inp1[5] = {
      "EUEhf32xvT89CYMQ5vcH6ySXNs3zHONABwX6crvFJPA",
      "o/g8f253znTJeLPUL9RqOIY/sfgXD+sWI4LmNOn9QzY=",
      "ZWUKerPaB0Cfp4M5WPg9+TJ/Ar0/cDMit7lzk1wsCPE=",
      "oIGaF3yJsE47uycQ4tiQB9oy8J9wVxjLnoWn3MRk4+Y=",
      "WFrn4zDymhPd7KQ3yUhInejYhf7DJoTyEx0kzYVKBZM=" };
   const std::string path1[3] = {
      "UubjZMTcp4WeyxhXcJ/wMtoHkNjiECe7O06wiXwXmoGg",
      "TDltFtR0f4caFSigQl+dtAI6SaqdujNF3s2PvuAYD0cv",
      "UqO0+wyk8maVvWG1g1RY2cn0v7dWAsIXMhHhnrLwvLKd" };
   const std::string path2[3] = {
      std::string(),
      std::string(),
      "TBCwOKsBxfQEjr57S2be+XJdvSnW9XFHSsDJWUn3QRPT" };

#if 0
   //8725ed2bbbe730afe563ff201f46f07d52c51e8a68a52bc5e9146fde0a96e825
   const std::string inp2[4] = {
      "/PafLqVayW8Yh9fGA50j0pctG8hHU4X7TisRenmavrY=",
      "dvaEORSIDLT9AwDJuaCzACdjjDida3Fx7JH9GynKgi8=",
      "7bwQ7H6yj078Komhz58NKG3yjrWdOi2XYx3D6UdNOqc",
      "wvfrsNv1QBKG8YNHJGjt3DQFq8bG9rh6I0AFzP0DSOg=" };
   merkGenPath(inp2,4,2);
#endif

   merkGenPath(inp1,5,2);
   merkVerifyPath(inp1[2], path1, 3);
   merkVerifyPath(inp1[4], path2, 3);

   return 0;
}
