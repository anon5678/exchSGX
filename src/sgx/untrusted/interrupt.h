#ifndef PROJECT_INTERRUPT_H
#define PROJECT_INTERRUPT_H

#include <atomic>

// this file deals with signals, esp. Ctrl-C

namespace exch
{
namespace interrupt
{
extern std::atomic<bool> quit;
void flipQuit(int n);
void init_signal_handler();

}  // namespace interrupt
}  // namespace exch

#endif  // PROJECT_INTERRUPT_H
