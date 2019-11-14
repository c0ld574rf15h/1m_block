#pragma once
#include <string>
#include <unordered_set>
using namespace std;

#define BUF_SIZE        4096
#define NUM_METHODS     6
#define HOST_NAME_SZ    100

void dump(const unsigned char* buf, int len);
bool check_host(int len, const unsigned char* payload, unordered_set<string> &filter);
bool isHTTP(const unsigned char* payload);
string extract_host(const unsigned char* payload);
bool filter_host(std::string host);