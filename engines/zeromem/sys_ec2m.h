#ifndef _SYS_EC2M_H_
#define _SYS_EC2M_H_

#define __NR_ec2m_alloc 312
#define __NR_ec2m_free 313
#define __NR_ec2m_setkey 314
#define __NR_ec2m_encrypt 315

#include "ec.h"

extern int sys_ec2m_alloc(void);
extern int sys_ec2m_free(int rid);
extern int sys_ec2m_setkey(int rid, mm_256* key, int a, int b);
extern int sys_ec2m_encrypt(int rid, mm256_point_t* bufin, mm256_point_t* bufout);

#endif
