#include "utils.h"
#include <iostream>
#include <cstdio>
#include <cstring>
#include <glog/logging.h>
using namespace std;

void dump(const unsigned char* buf, int len) {
    printf("\n");
	for (int i = 0; i < len; i++) {
		if (i % 16 == 0)
			printf("\n");
		printf("%c", buf[i]);
    }
    printf("\n");
}

bool check_host(int len, const unsigned char* payload, unordered_set<string> &filter) {
    bool ret = false;
    int ip_len = (payload[0] & 0x0F) << 2;
    int tcp_len = (payload[ip_len + 12] & 0xF0) >> 2;
    int offset = ip_len + tcp_len;

    if(isHTTP(payload+offset)) {
        string host = extract_host(payload+offset);
        LOG(INFO) << "Current host : " << host;
        if(filter.find(host) != filter.end())
            return true;
    }
    return false;
}

bool isHTTP(const unsigned char* http_field) {
    const char* http_methods[NUM_METHODS] = {
		"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS"
    };
    for(int i=0;i<NUM_METHODS;++i)
        if(!memcmp(http_field, http_methods[i], strlen(http_methods[i])))
            return true;
    return false;
}

string extract_host(const unsigned char* http_field) {
    string ret = "";
    int idx = 0;
    while(true) {
        if(!memcmp(http_field+idx, "Host: ", 6)) {
            idx += 6;
            for(int i=0;memcmp(http_field+idx+i, "\x0d\x0a", 2);++i)
                ret += http_field[idx+i];
            break;
        }
        ++idx;
    }
    return ret;
}