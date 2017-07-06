/*
 *  Borland C++ 32-bit compiler (BCC32). Use with mirdef.h32 
 *  Uses inline assembly feature. Suitable for Win32 Apps
 *  Also compatible with Microsoft Visual C++ 32-bit compiler
 */

#define ASM __asm__

int muldiv(a,b,c,m,rp)
int a,b,c,m,*rp;
{
        ASM ("movl   a,%eax");      
        ASM ("mull   b");          
        ASM ("addl   c,%eax");      
        ASM ("adcl   $0h,%edx");                 
        ASM ("divl   m");          
        ASM ("movl   rp,%ebx");     
        ASM ("movl   %edx,(%ebx)");              
}

int muldvm(a,c,m,rp)
int a,c,m,*rp;
{
        ASM ("movl   a,%edx");      
        ASM ("movl   c,%eax");      
        ASM ("divl   m");          
        ASM ("movl   rp,%ebx");     
        ASM ("movl   %edx,(%ebx)");              
}

int muldvd(a,b,c,rp)
int a,b,c,*rp;
{
        ASM ("movl   a,%eax");      
        ASM ("mull   b");          
        ASM ("addl   c,%eax");      
        ASM ("adcl   $0h,%edx");                 
        ASM ("movl   rp,%ebx");     
        ASM ("movl   %eax,(%ebx)");              
        ASM ("movl   %edx,%eax");
}

void muldvd2(a,b,c,rp)
int a,b,*c,*rp;
{
        ASM ("movl   a,%eax");      
        ASM ("mull   b");          
        ASM ("movl   c,%ebx");
        ASM ("addl   (%ebx),%eax");
        ASM ("adcl   $0h,%edx");
        ASM ("movl   rp,%esi");
        ASM ("addl   (%esi),%eax");
        ASM ("adcl   $0h,%edx");
        ASM ("movl   %eax,(%esi)");              
        ASM ("movl   %edx,(%ebx)");
}

