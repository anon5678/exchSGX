#ifndef EXCH_MERKPATH_H
#define EXCH_MERKPATH_H

#include <string>
#include <vector>

#define DBGMERK

using std::vector;
using std::string;

void merkGenPathHEX(const vector<string>& leaf_nodes, int index);
#ifdef DBGMERK
void testMerk();
#endif

#endif /* ifndef  EXCH_MERKPATH_H */
