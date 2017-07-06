/*
 *  Borland C++ 32-bit compiler (BCC32). Use with mirdef.h32 
 *  Uses inline assembly feature. Suitable for Win32 Apps
 *  Also compatible with Microsoft Visual C++ 32-bit compiler
 */

#define ASM __asm__

int muldiv(a,b,c,m,rp)
int a,b,c,m,*rp;
{
        ASM ("movl   %eax,a");      
        ASM ("mull   b");          
        ASM ("addl   %eax,c");      
        ASM ("adcl   %edx,0h");                 
        ASM ("divl   m");          
        ASM ("movl   %ebx,rp");     
        ASM ("movl   (%ebx),%edx");              
}

int muldvm(a,c,m,rp)
int a,c,m,*rp;
{
        ASM ("movl   %edx,a");      
        ASM ("movl   %eax,c");      
        ASM ("divl   m");          
        ASM ("movl   %ebx,rp");     
        ASM ("movl   (%ebx),%edx");              
}

int muldvd(a,b,c,rp)
int a,b,c,*rp;
{
        ASM ("movl   %eax,a");      
        ASM ("mull   b");          
        ASM ("addl   %eax,c");      
        ASM ("adcl   %edx,0h");                 
        ASM ("movl   %ebx,rp");     
        ASM ("movl   (%ebx),%eax");              
        ASM ("movl   %eax,%edx");
}

void muldvd2(a,b,c,rp)
int a,b,*c,*rp;
{
        ASM ("movl   %eax,a");      
        ASM ("mull   b");          
        ASM ("movl   %ebx,c");
        ASM ("addl   %eax,(%ebx)");
        ASM ("adcl   %edx,0h");
        ASM ("movl   %esi,rp");
        ASM ("addl   %eax,(esi)");
        ASM ("adcl   %edx,0h");
        ASM ("movl   (%esi),%eax");              
        ASM ("movl   (%ebx),%edx");
}

