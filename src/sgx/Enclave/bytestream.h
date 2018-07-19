#ifndef PROJECT_BYTESTREAM_H
#define PROJECT_BYTESTREAM_H

#include <vector>
#include <stdexcept>
#include <cstdint>
#include <cstddef>
#include <cstring>

#include "log.h"

class bytestream {
 private:
  std::vector<uint8_t> _data;
  int _rpos;

 public:
  bytestream() : _rpos(0) {};
  bytestream(std::vector<uint8_t> bytes) : _rpos(0) {
    _data.insert(_data.end(), bytes.begin(), bytes.end());
  }

  size_t read(char *to, size_t num) {
    LL_DEBUG("(rpos = %d) reading %d to %p", _rpos, num, to);

    if (num > _data.size() - _rpos) {
      return 0;
    }
    memcpy(to, _data.data() + _rpos, num);
    _rpos += num;

    LL_DEBUG("copied %d bytes", num);

    return num;
  }

  size_t write(char *from, size_t num) {
    _data.insert(_data.end(), from, from + num);

    return num;
  }

  const std::vector<uint8_t> &data() { return _data; }

  void reset() {
    _rpos = 0;
  }
};

#endif //PROJECT_BYTESTREAM_H
