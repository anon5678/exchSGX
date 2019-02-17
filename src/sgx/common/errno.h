#ifndef PROJECT_ERRNO_H
#define PROJECT_ERRNO_H

const static int NO_ERROR = 0;

#define SECRETKEY_SEALED_LEN 1024
#define SECKEY_LEN  32
#define PUBKEY_LEN  65
#define ADDRESS_LEN 20

#define HYBRID_KEY_NOT_PROVISIONED  -0x9001
#define RSA_KEY_NOT_PROVISIONED     -0x9002
#define BUFFER_TOO_SMALL            -0x8001


#define DEFINE_ERROR_CODE(name, reason, mask, num) const static int name##_##reason = -((mask << 16) + num);

DEFINE_ERROR_CODE(BLOCKFIFO, INVALID_INPUT, 0x10, 1)
DEFINE_ERROR_CODE(BLOCKFIFO, NOT_A_CHAIN, 0x10, 2)
DEFINE_ERROR_CODE(BLOCKFIFO, INSUFFICIENT_DIFFICULTY, 0x10, 3)

typedef int errno_t;

#endif //PROJECT_ERRNO_H
