#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <iostream>
#include <iomanip>
#include <cstring>

std::string base64_encode(const std::string &);
std::string base64_decode(const std::string &);

typedef unsigned long long cointype;
typedef unsigned char arrdigest[SHA256_DIGEST_LENGTH];

void hexdump(const unsigned char* data, int len) {
   std::cout << std::hex;
   for(int i=0; i<len; ++i)
      std::cout << std::setfill('0') << std::setw(2) << (int)data[i];
   std::cout << std::dec << std::endl;
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

void hash160(void const* const src, int len, void * const dst) {
   SHA256_CTX h1;
   unsigned char tmp[SHA256_DIGEST_LENGTH];
   SHA256_Init(&h1);
   SHA256_Update(&h1, (unsigned char*)src, len);
   SHA256_Final(tmp, &h1);
   RIPEMD160_CTX h2;
   RIPEMD160_Init(&h2);
   RIPEMD160_Update(&h2, tmp, SHA256_DIGEST_LENGTH);
   RIPEMD160_Final((unsigned char *)dst, &h2);
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
   int dirvec) {
   unsigned char curr[SHA256_DIGEST_LENGTH];
   const char * tmp;

   std::memcpy(curr, (base64_decode(leaf)).data(), 32);
   byte_swap(curr, 32);

   for(int i=0; dirvec>1; ++i,dirvec>>=1) {
      if( (branch[i]).empty() ) {
         sha256double(curr, curr, curr);
         continue;
      }
      tmp = (base64_decode(branch[i])).data();
      if(dirvec & 1)
         sha256double(curr, tmp, curr);
      else
         sha256double(tmp, curr, curr);
   }
   
   byte_swap(curr, 32);
   hexdump(curr, 32);
}

void fill_timelock_payment_template(unsigned char * aa,
   const char * RTEpk, int timeout, const char * refund) {
   int j=0;
   aa[j++] = 0x63; //op_if
   aa[j++] = 0xa8; //op_sha256 (rm)
   aa[j++] = 0x20; //32 bytes digest size (rm)
   std::memcpy(aa+j, (base64_decode("x3Xnt1ft5jDNCqERO9ECZhqziCnKUqZCKreChi8mhkY=")).data(), 32); //sha256 digest (rm)
   aa[j+32] = 0x88; //op_equalverify (rm)
   j+=33;
   aa[j++] = 0x21; //33 bytes pubkey size
   std::memcpy(aa+j, RTEpk, 33);
   aa[j+33] = 0xAC; //op_checksig
   j+=34;
   aa[j++] = 0x67; //op_else
   aa[j++] = 0x3; //timeout size
   aa[j++] = timeout >> 16;
   aa[j++] = timeout >> 8;
   aa[j++] = timeout;
   aa[j++] = 0xb1; //op_CLTV
   aa[j++] = 0x75; //op_drop
   aa[j++] = 0x21; //33 bytes pubkey size
   std::memcpy(aa+j, refund, 33);
   aa[j+33] = 0xAC; //op_checksig
   aa[j+34] = 0x68; //op_endif
}

cointype validateDeposit(const unsigned char * tx,
   const char * RTEpubkey, int timeout, const char * refund) {
   if(1 != tx[4]) return 0; //single input
   int j = 5+32+4+1+tx[5+32+4]+4+1; //skip to first output
   cointype r = tx[j++];
   for(int i=8; i<=56; i+=8)
      r += cointype(tx[j++]) << i;
   if(23 != tx[j++]) return 0; //p2sh size
   if(0xA9 != tx[j++]) return 0; //op_hash160
   if(0x14 != tx[j++]) return 0; //20 bytes
   if(0x87 != tx[j + 20]) return 0; //op_equal
   hexdump(tx+j, 20);

   unsigned char arr[114];
   fill_timelock_payment_template(arr,RTEpubkey,timeout,refund);
   unsigned char res[20];
   hash160(arr, 114, res);
   hexdump(res, 20);

   return r;
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

#if 0
   //8725ed2bbbe730afe563ff201f46f07d52c51e8a68a52bc5e9146fde0a96e825
   const std::string inp2[4] = {
      "/PafLqVayW8Yh9fGA50j0pctG8hHU4X7TisRenmavrY=",
      "dvaEORSIDLT9AwDJuaCzACdjjDida3Fx7JH9GynKgi8=",
      "7bwQ7H6yj078Komhz58NKG3yjrWdOi2XYx3D6UdNOqc",
      "wvfrsNv1QBKG8YNHJGjt3DQFq8bG9rh6I0AFzP0DSOg=" };
   merkGenPath(inp2,4,2);
#endif

#if 1
   //b42be2d0403e5a7336b1f5e2b5c344827177d191b1cbced3565b7ba138d8a83d
   const std::string inp1[5] = {
      "EUEhf32xvT89CYMQ5vcH6ySXNs3zHONABwX6crvFJPA",
      "o/g8f253znTJeLPUL9RqOIY/sfgXD+sWI4LmNOn9QzY=",
      "ZWUKerPaB0Cfp4M5WPg9+TJ/Ar0/cDMit7lzk1wsCPE=",
      "oIGaF3yJsE47uycQ4tiQB9oy8J9wVxjLnoWn3MRk4+Y=",
      "WFrn4zDymhPd7KQ3yUhInejYhf7DJoTyEx0kzYVKBZM=" };
   const std::string path1[3] = {
      "5uNkxNynhZ7LGFdwn/Ay2geQ2OIQJ7s7TrCJfBeagaA=",
      "OW0W1HR/hxoVKKBCX520AjpJqp26M0XezY++4BgPRy8=",
      "o7T7DKTyZpW9YbWDVFjZyfS/t1YCwhcyEeGesvC8sp0=" };
   const std::string path2[3] = {
      std::string(),
      std::string(),
      "ELA4qwHF9ASOvntLZt75cl29Kdb1cUdKwMlZSfdBE9M=" };
   merkGenPath(inp1,5,2);
   merkVerifyPath(inp1[2], path1, 13 /* 1RLR=1101 */ );
   merkVerifyPath(inp1[4], path2, 8 /* 1Lxx=10xx */ );
#endif

#if 1
   #include "txdata/tx390580base64.txt"
   merkGenPath(leaves390580,1182,664);

   unsigned char arr288bcaaa[223];
   std::memcpy(arr288bcaaa, (base64_decode(txin288bcaaa)).data(), 223);
   //byte_swap(arr288bcaaa, 223);

   SHA256_CTX h1,h2;
   unsigned char t1[SHA256_DIGEST_LENGTH];
   SHA256_Init(&h1);
   SHA256_Update(&h1, arr288bcaaa, 223);
   SHA256_Final(t1, &h1);
   SHA256_Init(&h2);
   SHA256_Update(&h2, t1, SHA256_DIGEST_LENGTH);
   SHA256_Final(t1, &h2);

   byte_swap(t1, 32);
   hexdump(t1, 32);

   const cointype amount = validateDeposit(arr288bcaaa,
      base64_decode("A9fGBSVEvELrK8DSfIhAFq25M/FVdqGi0hzU3Q8t4MN9").data(),
      0x389900,
      base64_decode("AhhEmJor16zRJ91+1Rqi9NVbMtu0FN5jJa434FwQZ1mN").data());
   std::cout << amount << std::endl;
#endif

   return 0;
}
