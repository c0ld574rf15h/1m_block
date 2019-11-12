#include <cstdlib>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <glog/logging.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include "utils.h"
using namespace std;

static u_int32_t print_pkt(struct nfq_data* tb) {
    int id = 0, ret = 0;
    unsigned char* data;

    struct nfqnl_msg_packet_hdr* ph;
    ph = nfq_get_msg_packet_hdr(tb);
    if(ph) id = ntohl(ph->packet_id);

    ret = nfq_get_payload(tb, &data);
    return id;
}

static int cb(struct nfq_q_handle* qh, struct nfgenmsg* nfmsg, struct nfq_data* nfa, void* data) {
    int id = print_pkt(nfa);
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, 0);  // How to alternate NULL in C++ ?
}

int main(int argc, char* argv[]) {
    google::InitGoogleLogging(argv[0]);
    google::LogToStderr();
    
    if(argc != 2) {
        LOG(ERROR) << "Requires text file as first argument";
        return -1;
    }

    struct nfq_handle* h = nfq_open();
    if(!h) {
        LOG(ERROR) << "Error during nfq_open()";
        return -1;
    }
    if(nfq_unbind_pf(h, AF_INET) < 0) {
        LOG(ERROR) << "Error during nfq_unbind_pf()";
        return -1;
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
            LOG(INFO) << "Packet received";
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