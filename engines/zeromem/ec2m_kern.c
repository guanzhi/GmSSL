#include "ec2m_kern.h"
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <unistd.h>
#include <malloc.h>
#include "util.h"

int sock_fd;

int init_netlink(int unit, int portId){
	struct sockaddr_nl src_addr;
    sock_fd=socket(PF_NETLINK, SOCK_RAW, unit);
    if(sock_fd<0)
		return -1;
	
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = portId;  /* self pid */
    /* interested in group 1<<0 */
    bind(sock_fd, (struct sockaddr*)&src_addr,
        sizeof(src_addr));         //绑定netlink   

	if(sock_fd < 0)
		return -1;
	
	return 0;
}

int send_request(const int func, const void* msg, int mlen)
{
	struct nlmsghdr *nlh = NULL;
	struct iovec iov;
	struct msghdr mhdr;
	struct sockaddr_nl dest_addr;
	struct ec2m_request_st req;
	const int len = mlen + sizeof(struct ec2m_request_st);
	
	req.func = func;
	req.len = len;

	memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0;   /* For Linux Kernel */
    dest_addr.nl_groups = 0; /* unicast */

	memset(&mhdr, 0, sizeof(mhdr));
    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(len));
    memset(nlh, 0, NLMSG_SPACE(len));
    nlh->nlmsg_len = NLMSG_SPACE(len);
    nlh->nlmsg_pid = getpid();
	
    nlh->nlmsg_flags = 0;

	memcpy((void*)NLMSG_DATA(nlh), &req, sizeof(req));
	memcpy((void*)NLMSG_DATA(nlh) + sizeof(req), msg, mlen);

    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;

    mhdr.msg_name = (void *)&dest_addr;
    mhdr.msg_namelen = sizeof(dest_addr);
    mhdr.msg_iov = &iov;
    mhdr.msg_iovlen = 1;

    sendmsg(sock_fd,&mhdr,0);   //通过netlink发送消息
	

	return OK;
}

int recv_response(void* buf, int len)
{
	struct ec2m_response_st resp;
	struct nlmsghdr *nlh = NULL;
	struct iovec iov;
	struct msghdr mhdr;
	struct sockaddr_nl dest_addr;
	int buflen;

    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0;   /* For Linux Kernel */
    dest_addr.nl_groups = 0; /* unicast */

	memset(&mhdr, 0, sizeof(mhdr));
    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
    memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
    nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;

    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;

    mhdr.msg_name = (void *)&dest_addr;
    mhdr.msg_namelen = sizeof(dest_addr);
    mhdr.msg_iov = &iov;
    mhdr.msg_iovlen = 1;

	buflen = recvmsg(sock_fd, &mhdr, 0);                  
	if(buflen < 0){
		fprintf(stderr, "invalid retval of recvmsg %d\n", buflen);
		
		return buflen;
	}

	buflen -= NLMSG_HDRLEN;
	assert(buflen >= sizeof(resp));
	memcpy(&resp, NLMSG_DATA(nlh), sizeof(resp));
	buflen -= sizeof(resp);
	assert(buflen == len);
	
	if (buflen > 0 && buf != NULL) {
		memcpy(buf, NLMSG_DATA(nlh) + sizeof(resp), buflen);
	}
	/* printf("resp: %d, len: %d\n", resp.result, buflen); */
	
	return resp.result;
}

int ec2m_kern_init()
{
	int r;
	
	r = init_netlink(NETLINK_ECC, getpid());

	if (r < 0)
		return r;
	
	return 0;
}

void ec2m_kern_clean()
{
	close(sock_fd);
}


int ec2m_import_key(mm_256* key)
{
	int r;
	
	/* printf("key: %016lx%016lx%016lx\n", key->iv[2], key->iv[1], key->iv[0]); */
	r = send_request(REQ_IMPORT_KEY, key, sizeof(mm_256));
	if (r < 0)
		return r;
	
	r = recv_response(NULL, 0);
	if (r < 0)
		return r;
	

	return 0;
	
}

int ec2m_private_operation(mm256_point_t*p, mm256_point_t*q)
{
	int r;

	r = send_request(REQ_PRIVATE_OP, p, sizeof(mm256_point_t));
	if (r < 0)
		return r;

	r = recv_response(q, sizeof(mm256_point_t));
	if (r < 0)
		return r;
		
	return 0;	
}
