#include "rte_udp.h"
#include <stdlib.h>
#include <netinet/in.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_kni.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "dns.h"    //移植SimpleDNS

#define NUM_MBUFS (4096-1)

#define BURST_SIZE	32
#define DNS_UDP_PORT 53

/**
*	ping包,以太网头+ip头+icmp头
*   ping之前一般会先发arp
*	arp包, 以太网头+arp头
*	dns包, 以太网头+ip头+udp头+dns头
*
*/

static uint32_t gSrcIp; //ip存储,4字节
static uint32_t gDstIp;

static uint8_t gSrcMac[RTE_ETHER_ADDR_LEN];  //mac地址存储,6字节
static uint8_t gDstMac[RTE_ETHER_ADDR_LEN];

static uint16_t gSrcPort;   //端口存储,2字节
static uint16_t gDstPort;


int gDpdkPortId = 0;  //网卡id

static const struct rte_eth_conf port_conf_default = {
	.rxmode = {.max_rx_pkt_len = RTE_ETHER_MAX_LEN }
};

struct rte_kni *global_kni = NULL; //定义全局kni

//设置网卡、设置rx队列、设置tx队列
static void ng_init_port(struct rte_mempool *mbuf_pool) {

	//获取可用的网卡数量
	uint16_t nb_sys_ports= rte_eth_dev_count_avail(); //
	if (nb_sys_ports == 0) {
		rte_exit(EXIT_FAILURE, "No Supported eth found\n");
	}

	//获取网卡信息
	struct rte_eth_dev_info dev_info;
	rte_eth_dev_info_get(gDpdkPortId, &dev_info); //
	
	//设置网卡1个rx队列,1个tx队列
	const int num_rx_queues = 1;
	const int num_tx_queues = 1;
	struct rte_eth_conf port_conf = port_conf_default;
	rte_eth_dev_configure(gDpdkPortId, num_rx_queues, num_tx_queues, &port_conf);

	//设置rx队列,队列id,队列存储mbuf的最大个数1024
	if (rte_eth_rx_queue_setup(gDpdkPortId, 0 , 1024, 
		rte_eth_dev_socket_id(gDpdkPortId),NULL, mbuf_pool) < 0) {
		rte_exit(EXIT_FAILURE, "Could not setup RX queue\n");
	}
	
	//设置tx队列,队列id,队列存储mbuf的最大个数1024
	struct rte_eth_txconf txq_conf = dev_info.default_txconf;
	txq_conf.offloads = port_conf.rxmode.offloads;
	if (rte_eth_tx_queue_setup(gDpdkPortId, 0 , 1024, 
		rte_eth_dev_socket_id(gDpdkPortId), &txq_conf) < 0) {
		rte_exit(EXIT_FAILURE, "Could not setup TX queue\n");
	}

	//启动网卡
	if (rte_eth_dev_start(gDpdkPortId) < 0 ) {
		rte_exit(EXIT_FAILURE, "Could not start\n");
	}

}

//打包udp包
static int ng_encode_udp_pkt(uint8_t *msg, unsigned char *data, uint16_t total_len) {

	// encode 

	// 1 ethhdr
	struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
	rte_memcpy(eth->s_addr.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
	rte_memcpy(eth->d_addr.addr_bytes, gDstMac, RTE_ETHER_ADDR_LEN);
	eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);
	

	// 2 iphdr 
	struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(msg + sizeof(struct rte_ether_hdr));
	ip->version_ihl = 0x45;
	ip->type_of_service = 0;
	ip->total_length = htons(total_len - sizeof(struct rte_ether_hdr));
	ip->packet_id = 0;
	ip->fragment_offset = 0;
	ip->time_to_live = 64; // ttl = 64
	ip->next_proto_id = IPPROTO_UDP;
	ip->src_addr = gSrcIp;
	ip->dst_addr = gDstIp;
	
	ip->hdr_checksum = 0;
	ip->hdr_checksum = rte_ipv4_cksum(ip);

	// 3 udphdr 

	struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(msg + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
	udp->src_port = gSrcPort;
	udp->dst_port = gDstPort;
	uint16_t udplen = total_len - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv4_hdr);
	udp->dgram_len = htons(udplen);

	rte_memcpy((uint8_t*)(udp+1), data, udplen);

	udp->dgram_cksum = 0;
	udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip, udp);

	struct in_addr addr;
	addr.s_addr = gSrcIp;
	printf(" --> src: %s:%d, ", inet_ntoa(addr), ntohs(gSrcPort));

	addr.s_addr = gDstIp;
	printf("dst: %s:%d\n", inet_ntoa(addr), ntohs(gDstPort));

	return 0;
}

//把封装好的udp协议数据组装到mbuf中,udp指向数据的指针和udp头+数据的长度
static struct rte_mbuf * ng_send(struct rte_mempool *mbuf_pool, uint8_t *data, uint16_t length) {

	const unsigned total_len = length + 34;  //42

	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
	if (!mbuf) {
		rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc\n");
	}
	mbuf->pkt_len = total_len;
	mbuf->data_len = total_len;

	uint8_t *pktdata = rte_pktmbuf_mtod(mbuf, uint8_t*);

	ng_encode_udp_pkt(pktdata, data, total_len);

	return mbuf;

}

//回调函数
static int gconfig_network_if(uint16_t port_id, uint8_t if_up){

	if(rte_eth_dev_is_valid_port(port_id)){
		return -EINVAL;
	}
	int ret = 0;
	if(if_up){
		rte_eth_dev_stop(port_id);
		ret = rte_eth_dev_start(port_id);
	}else {
		rte_eth_dev_stop(port_id);
	}
	if(ret<0){
		printf("Fail to start port:%d\n", port_id);
	}
	return 0;
}


int main(int argc, char *argv[]) {

	//环境初始化,检查巨页，内存大小,是否绑定网卡pci地址
	if (rte_eal_init(argc, argv) < 0) {
		rte_exit(EXIT_FAILURE, "Error with EAL init\n");
	}

	//创建内存池,NUM_MBUFS个mbuf,每个mbuf大小为RTE_MBUF_DEFAULT_BUF_SIZE
	struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("mbuf pool", NUM_MBUFS,
		0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (mbuf_pool == NULL) {
		rte_exit(EXIT_FAILURE, "Could not create mbuf pool\n");
	}

	//设置网卡、rx队列、tx队列、启动网卡
	ng_init_port(mbuf_pool);

	//开启混杂模式
	// rte_eth_promiscuous_enable(gDpdkPortId);

	//初始化kni
	rte_kni_init(gDpdkPortId);

	//kni分配内存,先设置conf、ops
	struct rte_kni_conf conf;
	memset(&conf, 0, sizeof(conf));
	snprintf(conf.name, RTE_KNI_NAMESIZE, "vEth%d",gDpdkPortId);  //设置虚拟网卡适配器名字为vEth0
	conf.group_id = gDpdkPortId;
	conf.mbuf_size = RTE_MBUF_DEFAULT_BUF_SIZE;
	rte_eth_macaddr_get(gDpdkPortId, (struct rte_ether_addr*)conf.mac_addr);
	rte_eth_dev_get_mtu(gDpdkPortId, &conf.mtu);

	struct rte_kni_ops ops;
	memset(&ops, 0, sizeof(ops));
	ops.port_id = gDpdkPortId;
	ops.config_network_if = gconfig_network_if; //回调函数

	//分配kni内存,此时会有vEth0网卡适配器,ifconfig vEth0 192.168.50.120 up
	global_kni = rte_kni_alloc(mbuf_pool, &conf, &ops);

	
	//移植SimpleDNS,源于https://github.com/mwarning/SimpleDNS
	struct Message msg;
  	memset(&msg, 0, sizeof(struct Message));
	//移植结束SimpleDNS-----------------------

	while (1) {

		//kni接收内核数据
		//执行rte_kni_rx_burst需要打开echo  1 > /sysdevices/virtual/net/vEth0/carrier
		unsigned kni_num_recvd = 0;
		struct rte_mbuf *kni_burst[BURST_SIZE];
		kni_num_recvd = rte_kni_rx_burst(global_kni, kni_burst,	1);
		if(kni_num_recvd>BURST_SIZE){
			rte_exit(EXIT_FAILURE, "Error receiving from eth\n");
		}
		//把kni接收数据走dpdk发送出去
		unsigned nb_tx =  rte_eth_tx_burst(gDpdkPortId, 0, kni_burst,kni_num_recvd);
		if(nb_tx<kni_num_recvd){
			for(unsigned i = 0; i< kni_num_recvd; i++){
				rte_pktmbuf_free(kni_burst[i]);
				kni_burst[i] = NULL;
			}
		}

		//dpdk接收网卡数据
		unsigned num_recvd = 0;
		struct rte_mbuf *mbufs[BURST_SIZE];
		num_recvd = rte_eth_rx_burst(gDpdkPortId, 0, mbufs, BURST_SIZE);
		if (num_recvd > BURST_SIZE) {
			rte_exit(EXIT_FAILURE, "rte_eth_rx_burst Error\n");
		}

		for (unsigned i = 0;i < num_recvd;i ++) {

			struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr*);
			if (ehdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {

				rte_kni_tx_burst(global_kni, &mbufs[i], 1);
				continue;
			}

			struct rte_ipv4_hdr *iphdr =  rte_pktmbuf_mtod_offset(mbufs[i], struct rte_ipv4_hdr *, 
				sizeof(struct rte_ether_hdr));
			
			if (iphdr->next_proto_id == IPPROTO_UDP) {
				printf("这是UDP包---------------");

				struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *)(iphdr + 1);

				//判断是否为53端口,dns的实现逻辑
				if(ntohs(udphdr->dst_port) == DNS_UDP_PORT){
					printf("这是53号端口---------------");

					uint16_t length = ntohs(udphdr->dgram_len);
					uint16_t nbytes = length - sizeof(struct rte_udp_hdr);
					uint8_t *data = (uint8_t*)(udphdr + 1);

					//移植SimpleDNS,源于https://github.com/mwarning/SimpleDNS
					free_questions(msg.questions);
					free_resource_records(msg.answers);
					free_resource_records(msg.authorities);
					free_resource_records(msg.additionals);
					memset(&msg, 0, sizeof(struct Message));

					//解码dns数据包
					if (!decode_msg(&msg, data, nbytes)) {
						rte_pktmbuf_free(mbufs[i]);
      					continue;
    				}

					//查询
					resolve_query(&msg);

					//重新封包
					uint8_t *p = data;
					if (!encode_msg(&msg, &p)) {
						rte_pktmbuf_free(mbufs[i]);
						continue;
					}

					//移植结束SimpleDNS-----------------------

					uint16_t len = p - data;

					//发送出去
					struct rte_mbuf *txbuf = ng_send(mbuf_pool, data, len+sizeof(struct rte_udp_hdr));
					rte_eth_tx_burst(gDpdkPortId, 0, &txbuf, 1);


				}
				//判断是否为8888号端口
				else if (ntohs(udphdr->dst_port) != 8888) {
					rte_pktmbuf_free(mbufs[i]);
					continue;
				}
				printf("这是8888号端口---------------");
				//以下执行8888号端口,把数据封装好原路返回
				rte_memcpy(gDstMac, ehdr->s_addr.addr_bytes, RTE_ETHER_ADDR_LEN);
				rte_memcpy(gSrcMac, ehdr->d_addr.addr_bytes, RTE_ETHER_ADDR_LEN);

				rte_memcpy(&gSrcIp, &iphdr->dst_addr, sizeof(uint32_t));
				rte_memcpy(&gDstIp, &iphdr->src_addr, sizeof(uint32_t));

				rte_memcpy(&gSrcPort, &udphdr->dst_port, sizeof(uint16_t));
				rte_memcpy(&gDstPort, &udphdr->src_port, sizeof(uint16_t));


				//在udp的最后添加'\0'结束符
				uint16_t length = ntohs(udphdr->dgram_len);
				*((char*)udphdr + length) = '\0';

				//打印源ip、目的ip、源端口、目的端口、数据
				struct in_addr addr;
				addr.s_addr = iphdr->src_addr;
				printf("src: %s:%d, ", inet_ntoa(addr), ntohs(udphdr->src_port));

				addr.s_addr = iphdr->dst_addr;
				printf("dst: %s:%d, %s\n", inet_ntoa(addr), ntohs(udphdr->dst_port), 
					(char *)(udphdr+1));

				//发送数据,这里(uint8_t *)(udphdr+1)指针指向了udp数据部分,length为udp头和数据总和
				struct rte_mbuf *txbuf = ng_send(mbuf_pool, (uint8_t *)(udphdr+1), length);
				rte_eth_tx_burst(gDpdkPortId, 0, &txbuf, 1);

				//释放mbuf
				rte_pktmbuf_free(txbuf);
				rte_pktmbuf_free(mbufs[i]);
			}else{
				//是ipv4但不是udp的包转给内核处理,这里测试ping命令
				rte_kni_tx_burst(global_kni, &mbufs[i], 1);

			}
			
		}

	}

}