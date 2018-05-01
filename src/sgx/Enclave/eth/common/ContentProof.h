#include "Proof.h"

class ContentProof : public Proof {
public:
    unsigned int pos;
    Address tokenAddr, userAddr;

    ContentProof(Bytes key, std::vector<Node> path, unsigned int pos, Address tokenAddr, Address userAddr):
        Proof(key, path), pos(pos), tokenAddr(tokenAddr), userAddr(userAddr) {}
};
