#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <errno.h>
#include <unordered_set>
#include <fstream>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <glog/logging.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include "utils.h"
using namespace std;

char hostname[HOST_NAME_SZ];
unordered_set<string> filter;

void read_file(const char* filename) {
    string host;
    ifstream in(filename);
    while(getline(in, host))
        filter.insert(host);
    LOG(INFO) << "Read " << filter.size() << " domains from file " << filename;
    in.close();
}

static u_int32_t print_pkt(struct nfq_data* tb, bool* flag) {
    int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi; 
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
	}
	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);
	}
	mark = nfq_get_nfmark(tb);
	ifi = nfq_get_indev(tb);
	ifi = nfq_get_outdev(tb);
	ifi = nfq_get_physindev(tb);
	ifi = nfq_get_physoutdev(tb);
    ret = nfq_get_payload(tb, &data);

    *flag = check_host(ret, (const unsigned char*)data, filter);
    return id;
}

static int cb(struct nfq_q_handle* qh, struct nfgenmsg* nfmsg, struct nfq_data* nfa, void* data) {
    bool flag = false;
    int id = print_pkt(nfa, &flag);
    if(flag) {
        LOG(INFO) << "Droping packet";
        return nfq_set_verdict(qh, id, NF_DROP, 0, 0);  // How to alternate NULL in C++ ?
    }
    else {
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, 0);
    }
}

int main(int argc, char* argv[]) {
    google::InitGoogleLogging(argv[0]);
    google::LogToStderr();
    
    if(argc != 2) {
        LOG(ERROR) << "Requires text file as first argument";
        return -1;
    }

    read_file((const char*) argv[1]);

    struct nfq_handle* h = nfq_open();
    if(!h) {
        LOG(ERROR) << "Error during nfq_open()";
        exit(1);
    }
    if(nfq_unbind_pf(h, AF_INET) < 0) {
        LOG(ERROR) << "Error during nfq_unbind_pf()";
        exit(1);
    }

    struct nfq_q_handle* qh = nfq_create_queue(h, 0, &cb, NULL);
    if(!qh) {
        LOG(ERROR) << "Error during nfq_q_handle()";
        return -1;
    }
    if(nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xFFFF) < 0) {
        LOG(ERROR) << "Can't set packet_copy mode";
        return -1;
    }

    int rv, fd = nfq_fd(h);
    char buf[BUF_SIZE] __attribute__ ((aligned));
    while(true) {
        if((rv = recv(fd, buf, sizeof(buf), 0)) >= 0){
            // LOG(INFO) << "Packet received";
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        if(rv < 0 && errno == ENOBUFS) {
            LOG(WARNING) << "Losing packets";
            continue;
        }
        perror("recv failed");
        break;
    }

    LOG(INFO) << "Unbinding from queue";
    nfq_destroy_queue(qh);

#ifdef INSANE
    LOG(INFO) << "Unbinding from AF_INET";
    nfq_unbind_pf(h, AF_INET);
#endif

    LOG(INFO) << "Closing library handle";
    nfq_close(h);

    return 0;
}