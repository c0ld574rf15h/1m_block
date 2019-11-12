#include "utils.h"
#include <iostream>

void dump(const char* buf, int len) {
    for(int i=0;i<len;++i) {
        if(i%16 == 0) std::cout << '\n';
        std::cout << buf[i];
    }
}