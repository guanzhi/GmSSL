/*
 *  Borland C++ 32-bit compiler (BCC32). Use with mirdef.h32 
 *  Uses inline assembly feature. Suitable for Win32 Apps
 *  Also compatible with Microsoft Visual C++ 32-bit compiler
 */

#define ASM _asm

int muldiv(a,b,c,m,rp)
int a,b,c,m,*rp;
{
        ASM mov   eax,DWORD PTR a      
        ASM mul   DWORD PTR b          
        ASM add   eax,DWORD PTR c      
        ASM adc   edx,0h                 
        ASM div   DWORD PTR m          
        ASM mov   ebx,DWORD PTR rp     
        ASM mov   [ebx],edx              
}

int muldvm(a,c,m,rp)
int a,c,m,*rp;
{
        ASM mov   edx,DWORD PTR a      
        ASM mov   eax,DWORD PTR c      
        ASM div   DWORD PTR m          
        ASM mov   ebx,DWORD PTR rp     
        ASM mov   [ebx],edx              
}

int muldvd(a,b,c,rp)
int a,b,c,*rp;
{
        ASM mov   eax,DWORD PTR a      
        ASM mul   DWORD PTR b          
        ASM add   eax,DWORD PTR c      
        ASM adc   edx,0h                 
        ASM mov   ebx,DWORD PTR rp     
        ASM mov   [ebx],eax              
        ASM mov   eax,edx
}

void muldvd2(a,b,c,rp)
int a,b,*c,*rp;
{
        ASM mov   eax,DWORD PTR a      
        ASM mul   DWORD PTR b          
        ASM mov   ebx,DWORD PTR c
        ASM add   eax,[ebx]
        ASM adc   edx,0h
        ASM mov   esi,DWORD PTR rp
        ASM add   eax,[esi]
        ASM adc   edx,0h
        ASM mov   [esi],eax              
        ASM mov   [ebx],edx
}

