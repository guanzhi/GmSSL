
#define SMS4_NUM_ROUNDS_BS		32
typedef struct 
{
	unsigned __int64 rkh[SMS4_NUM_ROUNDS_BS][4];
	unsigned __int64 rkl[SMS4_NUM_ROUNDS_BS][4];
} sms4_key_t_bs;


#define FK_BS00h (0xaaaaaaaaaaaaaaaa)
#define FK_BS00l (0x3333333333333333)
#define FK_BS01h (0xbbbbbbbbbbbbbbbb)
#define FK_BS01l (0x1111111111111111)
#define FK_BS02h (0xbbbbbbbbbbbbbbbb)
#define FK_BS02l (0xaaaaaaaaaaaaaaaa)
#define FK_BS03h (0xcccccccccccccccc)
#define FK_BS03l (0x6666666666666666)

#define FK_BS10h (0x5555555555555555)
#define FK_BS10l (0x6666666666666666)
#define FK_BS11h (0xaaaaaaaaaaaaaaaa)
#define FK_BS11l (0xaaaaaaaaaaaaaaaa)
#define FK_BS12h (0x3333333333333333)
#define FK_BS12l (0x3333333333333333)
#define FK_BS13h (0x5555555555555555)
#define FK_BS13l (0x0000000000000000)
//0x677d9197, 0xb27022dc,
#define FK_BS20h (0x6666666666666666)
#define FK_BS20l (0x7777777777777777)
#define FK_BS21h (0x7777777777777777)
#define FK_BS21l (0xdddddddddddddddd)
#define FK_BS22h (0x9999999999999999)
#define FK_BS22l (0x1111111111111111)
#define FK_BS23h (0x9999999999999999)
#define FK_BS23l (0x7777777777777777)

#define FK_BS30h (0xbbbbbbbbbbbbbbbb)
#define FK_BS30l (0x2222222222222222)
#define FK_BS31h (0x7777777777777777)
#define FK_BS31l (0x0000000000000000)
#define FK_BS32h (0x2222222222222222)
#define FK_BS32l (0x2222222222222222)
#define FK_BS33h (0xdddddddddddddddd)
#define FK_BS33l (0xcccccccccccccccc)

void sms4_set_encrypt_key_bs(sms4_key_t_bs *key,unsigned __int64 *user_keyh,unsigned __int64 *user_keyl);
void SMS4_encrypt_bs(sms4_key_t_bs *key,unsigned __int64 *INh,unsigned __int64 *INl,unsigned __int64 *OUTh,unsigned __int64 *OUTl);








