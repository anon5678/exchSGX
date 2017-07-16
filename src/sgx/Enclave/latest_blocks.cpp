//
// Created by fanz on 7/13/17.
//

#include "latest_blocks.h"
#include "pprint.h"
#include "Log.h"
#include "bitcoin/utilstrencodings.h"

#include <vector>
#include <iostream>

LatestBlocks<512> blockchain;

extern "C" {
void push(const char*);
}

void push(const char* header_hex) {
  LL_CRITICAL("Got %s", header_hex);

  if (160 != strlen(header_hex)) {
    LL_CRITICAL("invalid header");
  }

  std::vector<unsigned char> header = ParseHex(header_hex);

  hexdump("header", header.data(), header.size());



  CBlockHeader blockHeader;
}
