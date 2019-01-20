// Copyright 2013, 2014 by Martin Moene
//
// lest is based on ideas by Kevlin Henney, see video at
// http://skillsmatter.com/podcast/agile-testing/kevlin-henney-rethinking-unit-testing-in-c-plus-plus
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE.txt or copy at http://www.boost.org/LICENSE_1_0.txt)

#ifndef LEST_LEST_HPP_INCLUDED
#define LEST_LEST_HPP_INCLUDED

#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <cstddef>

#include "../utils.h"

#ifdef __clang__
# pragma clang diagnostic ignored "-Wunused-value"
#elif defined __GNUC__
# pragma GCC   diagnostic ignored "-Wunused-value"
#endif

#ifndef lest_NO_SHORT_ASSERTION_NAMES
# define CASE             lest_CASE
# define TEST             lest_TEST
# define EXPECT           lest_EXPECT
# define EXPECT_NOT       lest_EXPECT_NOT
# define EXPECT_NO_THROW  lest_EXPECT_NO_THROW
# define EXPECT_THROWS    lest_EXPECT_THROWS
# define EXPECT_THROWS_AS lest_EXPECT_THROWS_AS
#endif

#define lest_TEST \
    lest_CASE

#define lest_CASE(name, ...) \
    name, [__VA_ARGS__]

#define lest_EXPECT(expr) \
    do { \
        try \
        { \
            if ( ! (expr) ) \
                throw lest::failure{ lest_LOCATION, #expr }; \
        } \
        catch(...) \
        { \
            lest::inform( lest_LOCATION, #expr ); \
        } \
    } while ( lest::is_false() )

#define lest_EXPECT_NOT(expr) \
    lest_EXPECT( !(expr) )

#define lest_EXPECT_NO_THROW(expr) \
    do \
    { \
        try { expr; } \
        catch (...) { lest::inform( lest_LOCATION, #expr ); } \
    } while ( lest::is_false() )

#define lest_EXPECT_THROWS(expr) \
    do \
    { \
        try { expr; } catch (...) { break; } \
        throw lest::expected{ lest_LOCATION, #expr }; \
    } while ( lest::is_false() )

#define lest_EXPECT_THROWS_AS(expr, excpt) \
    do \
    { \
        try { expr; } catch ( excpt & ) { break; } catch (...) {} \
        throw lest::expected{ lest_LOCATION, #expr, lest::of_type( #excpt ) }; \
    } while ( lest::is_false() )

#define lest_LOCATION lest::location{__FILE__, __LINE__}

namespace lest {

using text = std::string;

struct test {
  const text name;
  const std::function<void()> behaviour;
};

struct location {
  const text file;
  const int line;

  location(text file, int line)
      : file(file), line(line) {}
};

struct comment {
  const text info;

  comment(text info) : info(info) {}
  explicit operator bool() { return !info.empty(); }
};

struct message : std::runtime_error {
  const text kind;
  const location where;
  const comment note;

  ~message() throw() {}   // GCC 4.6

  message(text kind, location where, text expr, text note = "")
      : std::runtime_error(expr), kind(kind), where(where), note(note) {}
};

struct failure : message {
  failure(location where, text expr)
      : message{"failed", where, expr} {}
};

struct expected : message {
  expected(location where, text expr, text excpt = "")
      : message{"failed: didn't get exception", where, expr, excpt} {}
};

struct unexpected : message {
  unexpected(location where, text expr, text note = "")
      : message{"failed: got unexpected exception", where, expr, note} {}
};

inline bool is_false() { return false; }
inline bool is_true(bool flag) { return flag; }

inline text with_message(text message) {
  return "with message \"" + message + "\"";
}

inline text of_type(text type) {
  return "of type " + type;
}

inline void inform(location where, text expr) {
  try {
    throw;
  }
  catch (lest::message const &) {
    throw;
  }
  catch (std::exception const &e) {
    throw lest::unexpected{where, expr, lest::with_message(e.what())}; \

  }
  catch (...) {
    throw lest::unexpected{where, expr, "of unknown type"}; \

  }
}

inline text pluralise(text word, int n) {
  return n == 1 ? word : word + "s";
}

//inline std::ostream & operator<<( std::ostream & os, comment note )
//{
//    return os << (note ? " " + note.info : "" );
//}

//inline std::ostream & operator<<( std::ostream & os, location where )
//{
//#ifdef __GNUG__
//    return os << where.file << ":" << where.line;
//#else
//    return os << where.file << "(" << where.line << ")";
//#endif
//}


inline void report(message const &e, std::string test) {
//  os << e.where << ": " << e.kind << e.note << ": " << test << ": " << e.what() << std::endl;
  printf_std("%s:%d: %s %s: %s: %s\n",
             e.where.file.c_str(), e.where.line,
             e.kind.c_str(),
             e.note.info.c_str(),
             test.c_str(),
             "",
             e.what());
}

template<std::size_t N>
int run(test const (&specification)[N]) {
  int failures = 0;

  for (auto &testing : specification) {
    try {
      testing.behaviour();
    }
    catch (message const &e) {
      ++failures;
      report(e, testing.name);
    }
  }

  if (failures > 0) {
    printf_std("%d out of %d %s failed\n", failures, N, pluralise("test", N).c_str());
  } else {
    printf_std("All (%d) tests passed\n", N);
  }

  return failures;
}

} // namespace lest

#endif // LEST_LEST_HPP_INCLUDED
