
#ifndef FRONTRUNNING_DETECTION_FIXEDDECIMAL_H
#define FRONTRUNNING_DETECTION_FIXEDDECIMAL_H

//#include <tcl.h>

template<typename T,int E>
class FixedDecimal {
private:
    static inline T _genFactor() {
        T res = 1;
        for (int i = 1; i <= E; ++i) {
            res *= 10;
        }
        return res;
    }
    static T factor;
    T value;
public:

    FixedDecimal() = default;

    explicit FixedDecimal(double v) : value(static_cast<T>(v * factor)) {}

    explicit FixedDecimal(T v): value(v * factor) {}

    explicit FixedDecimal(int v): value(v * factor) {}

    FixedDecimal& operator += (const FixedDecimal& rhs) {
        value += rhs.value;
        return *this;
    }

    FixedDecimal& operator -= (const FixedDecimal& rhs) {
        value -= rhs.value;
        return *this;
    }

    FixedDecimal& operator *= (const FixedDecimal& rhs) {
        value *= rhs.value;
        value /= factor;
        return *this;
    }

    FixedDecimal& operator /= (const FixedDecimal& rhs) {
        value /= rhs.value;
        value *= factor;
        return *this;
    }


    FixedDecimal& operator *= (T x) {
        value *= x;
        return *this;
    }

    FixedDecimal& operator /= (T x) {
        value /= x;
        return *this;
    }

    double toDouble( ) const {
        return double(value) / factor;
    }
    T round() {
        T res = value / factor;
        T remainder = value % factor;

        if(remainder >= factor / 10 * 6) { // >= .6
            res += 1;
        } else if(remainder >= factor / 10 * 5) {  // = .5
            if(remainder % (factor / 10) >= (factor / 100)) { // =.5x (x > 0)
                res += 1;
            } else if(res % 2 == 0){  // = x.50 (x is even)
                res += 1;
            }
        }
        return res;
    }


    friend FixedDecimal operator + (FixedDecimal lhs, const FixedDecimal& rhs) { return lhs += rhs; }

    friend FixedDecimal operator - (FixedDecimal lhs, const FixedDecimal& rhs) { return lhs -= rhs; }

    friend FixedDecimal operator * (FixedDecimal lhs, const FixedDecimal& rhs) { return lhs *= rhs; }

    friend FixedDecimal operator / (FixedDecimal lhs, const FixedDecimal& rhs) { return lhs /= rhs; }

    friend FixedDecimal operator * (FixedDecimal lhs, const T& rhs) { return lhs *= rhs; }

    friend FixedDecimal operator / (FixedDecimal lhs, const T& rhs) { return lhs /= rhs; }


    bool operator == (const FixedDecimal& rhs) const { return value == rhs.value; }

    bool operator != (const FixedDecimal& rhs) const { return value != rhs.value; }

    bool operator < (const FixedDecimal& rhs) const { return value < rhs.value; }

    bool operator <= (const FixedDecimal& rhs) const { return value <= rhs.value; }

    bool operator > (const FixedDecimal& rhs) const { return value > rhs.value; }

    bool operator >= (const FixedDecimal& rhs) const { return value >= rhs.value; }

};

template <typename T,int E>
T FixedDecimal<T, E>::factor = FixedDecimal<T, E>::_genFactor();

#endif //FRONTRUNNING_DETECTION_FIXEDDECIMAL_H
