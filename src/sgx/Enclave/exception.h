#ifndef PROJECT_EXCEPTION_H
#define PROJECT_EXCEPTION_H

#include <exception>
#include <string>

namespace exch
{
namespace enclave
{
class Exception : public std::exception
{
 private:
  int code;
  std::string msg;

 public:
  Exception(int code, std::string msg) : code(code), msg(std::move(msg)) {}
  const char* what() const noexcept override { return msg.c_str(); }
  int getErrorCode() const noexcept { return code; }
};
}  // namespace enclave
}  // namespace exch

#endif  // PROJECT_EXCEPTION_H
