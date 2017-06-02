#include "ec.h"
#include "string.h"
#include "stdio.h"

int is_one(mm_256* a) 
{
	int i;
	if (a->iv[0] != 1)
		return 0;
	
	for (i = 1; i < 4; i++) {
		if (a->iv[i] != 0)
			return 0;
	}

	return 1;
	
}

void shift_right(mm_256* a)
{
	int i;
	
	for (i = 0; i < 3; i++) {
		a->iv[i] = (a->iv[i] >> 1) | (a->iv[i + 1] << 63);
	}
	a->iv[3] >>= 1;
}

void add(mm_256* a, mm_256*b) 
{
	int i;
	
	for (i = 0; i < 4; i++) {
		b->iv[i] = b->iv[i] ^ a->iv[i];
	}
}

int deg(mm_256* a) 
{
	int cnt = 0;
	int i;
	uint64_t c;
	
	for (i = 3; i >= 0; i--) {
		if (a->iv[i] != 0) {
			break;
		}
	}
	cnt = i * 64;
	c = a->iv[i];
	while (c != 0) {
		cnt ++;
		c >>= 1;
	}
	return cnt;
}

void gf2m_inv(mm_256* a, mm_256 *r)
{
	mm_256 b, c, u, v, f, t;
	
	// b = 1
	memset(&b, 0, sizeof(b));
	b.iv[0] = 1;
	// c = 0
	memset(&c, 0, sizeof(c));
	// u = a
	u = *a;
	// v = f
	memset(&v, 0, sizeof(v));
	memset(&f, 0, sizeof(f));
	f.bv[0] = 0xc9;
	f.bv[20] = 0x8;
	v = f;

	while (1) {
		while ((u.bv[0] & 0x1) == 0) {
			shift_right(&u);
			
			if ((b.iv[0] & 0x1) != 0) {
				add(&f, &b);
			}
			shift_right(&b);
		}
		if (is_one(&u))
			break;
		
		if (deg(&u) < deg(&v)) {
			t = u;
			u = v;
			v = t;
			
			t = b;
			b = c;
			c = t;
		}
		add(&v, &u);
		add(&c, &b);
		/* break; */
	}
	
	*r = b;
}
