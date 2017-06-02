#include <unistd.h>
#include "sys_ec2m.h"

int sys_ec2m_alloc(void)
{
	return syscall(__NR_ec2m_alloc);
}

int sys_ec2m_free(int rid)
{
	return syscall(__NR_ec2m_free, rid);
}

int sys_ec2m_setkey(int rid, mm_256* key, int a, int b)
{
	return syscall(__NR_ec2m_setkey, rid, (void*)key, a, b);
}

int sys_ec2m_encrypt(int rid, mm256_point_t* bufin, mm256_point_t* bufout)
{
	return syscall(__NR_ec2m_encrypt, rid, (void*)bufin, (void*)bufout);
}
