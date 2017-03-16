#include <linux/version.h>
#include <linux/types.h>

#include <linux/module.h>
#include <linux/smp.h>

#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include "../ec2m_kern.h"
#include "../ec.h"

unsigned int sqr_table[1 << 16];
struct sock *sock_fd = NULL;

mm_256 gkey;

void init_sqr_table(void){
	unsigned int i, j;
	unsigned int t;
	unsigned int n;
	for(i = 0; i < sizeof(sqr_table) / sizeof(sqr_table[0]); i++){
		t = 0;
		j = i;
		n = 16;
		while(n-- > 0){
			t = t << 2;
			t |= ((j >> n) & 0x1);
		}
		sqr_table[i] = t;
	}
}

void import_key(void* info) {
	mm_256* key;
	mm_256 tkey;

	int cpu_id;
	unsigned long irqs;
	cpu_id = get_cpu();
	local_irq_save(irqs);
	
	//printk(KERN_INFO"%s on %d\n", __FUNCTION__, cpu_id);
	key = (mm_256*)info;
	// print value in dr0-3 previously
	__asm__(
		"movq %%dr0, %%rax\n\t"
		"vmovq %%rax, %%xmm15\n\t"
		"movq %%dr1, %%rax\n\t"
		"vpinsrq $1, %%rax, %%xmm15, %%xmm15\n\t"
		"movq %%dr2, %%rax\n\t"
		"vmovq %%rax, %%xmm14\n\t"
		"vinsertf128 $1, %%xmm14, %%ymm15, %%ymm15\n\t"
		"vmovdqu %%ymm15, %0\n\t"
		:"=m"(tkey)
		:
		: "rax", "memory"
		);
	
	//printk(KERN_INFO"debug regs:%016llx%016llx%016llx%016llx\n", tkey.iv[3], tkey.iv[2], tkey.iv[1], tkey.iv[0]);
	//printk(KERN_INFO"key: %016llx%016llx%016llx\n", key->iv[2], key->iv[1], key->iv[0]);
	gkey = *key;
	
	
	__asm__(
		"movq %0, %%dr0\n"
		"movq %1, %%dr1\n"
		"movq %2, %%dr2\n"
		:
		:"r"(key->iv[0]),"r"(key->iv[1]),"r"(key->iv[2])
		: "memory"
		);
	local_irq_restore(irqs);
	put_cpu();
}

int k_ec2m_import_key(mm_256* key) 
{
	import_key(key);
	smp_call_function(import_key, key, 1);
	return OK;
}

int k_ec2m_private_op(mm256_point_t* Q, mm256_point_t* P)
{
	int cpu_id;
	unsigned long irqs;
	cpu_id = get_cpu();
	local_irq_save(irqs);
	
	//printk(KERN_INFO"%s on %d\n", __FUNCTION__, cpu_id);

	__asm__ __volatile__(
		"movq %%dr0, %%rax\n\t"
		"vmovq %%rax, %%xmm15\n\t"
		"movq %%dr1, %%rax\n\t"
		"vpinsrq $1, %%rax, %%xmm15, %%xmm15\n\t"
		"movq %%dr2, %%rax\n\t"
		"vmovq %%rax, %%xmm14\n\t"
		"vinsertf128 $1, %%xmm14, %%ymm15, %%ymm15\n\t"
		:
		:
		: "rax", "memory"
		);
	gf2_point_mul_with_preset_key(P, Q, 1, 1);

	local_irq_restore(irqs);
	put_cpu();
	
	return OK;
}


void nl_recv_msg(struct sk_buff* skb){
	struct nlmsghdr *nlh;
	struct sk_buff* out;
	struct ec2m_request_st* req;
	struct ec2m_response_st resp;
	int pid;
	int size;
	char *buf;
	int r;
	
	nlh=(struct nlmsghdr*)skb->data;
	size = nlmsg_len(nlh);// - NLMSG_HDRLEN;

	pid = nlh->nlmsg_pid; /*pid of sending process */
	/* printk(KERN_INFO "Netlink received a new msg from %d, size: %d\n", pid, size); */
	buf = nlmsg_data(nlh);
	req = (struct ec2m_request_st*)buf;
	/* printk(KERN_INFO "got a request: %d, len: %d", req->func, req->len); */
	
	switch (req->func) {
	case REQ_IMPORT_KEY:
	{
		mm_256* key;
		key = (mm_256*) (buf + sizeof(struct ec2m_request_st));
		resp.result = k_ec2m_import_key(key);
		size = sizeof(struct ec2m_response_st);
		buf = kmalloc(size, GFP_KERNEL);
		memcpy(buf, &resp, sizeof(resp));
		break;
	}
	case REQ_PRIVATE_OP:
	{
		mm256_point_t* P;
		mm256_point_t Q;
		P = (mm256_point_t*) (buf + sizeof(struct ec2m_request_st));
		resp.result = k_ec2m_private_op(&Q, P);
		size = sizeof(struct ec2m_response_st) + sizeof(mm256_point_t);
		buf = kmalloc(size, GFP_KERNEL);
		memcpy(buf, &resp, sizeof(resp));
		memcpy(buf + sizeof(resp), &Q, sizeof(Q));
		break;
	}

	}

	out = nlmsg_new(size, 0);
	nlh = nlmsg_put(out, 0, 0, NLMSG_DONE, size, 0);
	NETLINK_CB(out).dst_group = 0; /* not in mcast group */
	memcpy(nlmsg_data(nlh), buf, size);
	r = nlmsg_unicast(sock_fd, out, pid);
	if (r < 0){
		printk(KERN_INFO "forward msg to %d failed, err code %d\n", pid, r);
	}
	kfree(buf);
}


int init_netlink(void){
	struct netlink_kernel_cfg cfg = {0};
	cfg.input = nl_recv_msg;
	sock_fd = netlink_kernel_create(&init_net, NETLINK_ECC, &cfg );

    if(!sock_fd)
    {
        printk(KERN_ALERT "Error creating socket.\n");
        return -1;
    }
	printk(KERN_ALERT "creating socket successfully.\n");

	return 0;
}



int __init ecc_init(void) {
	// init netlink
	init_netlink();
	init_sqr_table();
	
	return 0;
}


void __exit ecc_exit(void) {
	// netlink clean up
	if(sock_fd != NULL)
		netlink_kernel_release(sock_fd);	
}


module_init(ecc_init);
module_exit(ecc_exit);


MODULE_LICENSE("GPL");
