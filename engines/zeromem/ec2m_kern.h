#ifndef _EC2M_KERN_H_
#define _EC2M_KERN_H_

#define NETLINK_ECC 31
#define MAX_PAYLOAD 1024

#define REQ_IMPORT_KEY 1
#define REQ_PRIVATE_OP 2

#define OK 0
#define FAIL -1

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif
#include "ec.h"

struct ec2m_request_st {
	int func;
	int len;
};

struct ec2m_response_st
{
	int result;
};

extern int ec2m_kern_init(void);
extern void ec2m_kern_clean(void);

extern int ec2m_import_key(mm_256 *key);
extern int ec2m_private_operation(mm256_point_t*p, mm256_point_t*q);

#endif
