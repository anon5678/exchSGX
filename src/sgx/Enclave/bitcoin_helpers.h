#ifndef TESSERACT_BITCOIN_HELPERS_H
#define TESSERACT_BITCOIN_HELPERS_H

#include "bitcoin/script/script.h"
#include <vector>

std::string ScriptToAsmStr(const CScript& script);

#endif //TESSERACT_BITCOIN_HELPERS_H
