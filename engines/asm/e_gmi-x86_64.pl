#!/usr/bin/env perl

# ====================================================================
# Written by Yun Shen <yunshe@via-alliance.com> and 
# Kai Li <kelvinkli@via-alliance.com>, and refer to the code 
# written by Andy Polyakov <appro@openssl.org> for the OpenSSL
# project. The module is, however, dual licensed under OpenSSL and
# CRYPTOGAMS licenses depending on where you obtain it. For further
# details see http://www.openssl.org/~appro/cryptogams/.
# ====================================================================

# ====================================================================
# Copyright 2016 Shanghai Zhaoxin Semiconductor Co., Ltd. ALL RIGHTS RESERVED.
# ====================================================================

# May 2016
#
# Assembler helpers for Padlock engine. See even e_gmi-x86.pl for
# details.

$flavour = shift;
$output  = shift;
if ($flavour =~ /\./) { $output = $flavour; undef $flavour; }

$win64=0; $win64=1 if ($flavour =~ /[nm]asm|mingw64/ || $output =~ /\.asm$/);

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
( $xlate="${dir}x86_64-xlate.pl" and -f $xlate ) or
( $xlate="${dir}../../crypto/perlasm/x86_64-xlate.pl" and -f $xlate) or
die "can't locate x86_64-xlate.pl";

open OUT,"| \"$^X\" $xlate $flavour $output";
*STDOUT=*OUT;

$code=".text\n";

%PADLOCK_PREFETCH=(ecb=>128, cbc=>64, ctr32=>32);	# prefetch errata
$PADLOCK_CHUNK=512;	# Must be a power of 2 between 32 and 2^20

$ctx="%rdx";
$out="%rdi";
$inp="%rsi";
$len="%rcx";
$chunk="%rbx";

($arg1,$arg2,$arg3,$arg4)=$win64?("%rcx","%rdx","%r8", "%r9") : # Win64 order
                                 ("%rdi","%rsi","%rdx","%rcx"); # Unix order

$code.=<<___;

.globl	zx_gmi_capability
.type	zx_gmi_capability,\@abi-omnipotent
.align	16
zx_gmi_capability:
	mov	%rbx,%r8
	xor	%eax,%eax
	cpuid
	xor	%eax,%eax
	cmp	\$`"0x".unpack("H*",'hS  ')`,%ebx
	jne	.zx_Lnoluck
	cmp	\$`"0x".unpack("H*",'hgna')`,%edx
	jne	.zx_Lnoluck
	cmp	\$`"0x".unpack("H*",'  ia')`,%ecx
	jne	.zx_Lnoluck
	mov	\$0xC0000000,%eax
	cpuid
	mov	%eax,%edx
	xor	%eax,%eax
	cmp	\$0xC0000001,%edx
	jb	.zx_Lnoluck
	mov	\$0xC0000001,%eax
	cpuid
	mov	%edx,%eax
	and	\$0xffffffef,%eax
	or	\$0x10,%eax		# set Nano bit#4
.zx_Lnoluck:
	mov	%r8,%rbx
	ret
.size	zx_gmi_capability,.-zx_gmi_capability

.globl	gmi_reload_key
.type	gmi_reload_key,\@abi-omnipotent
.align	16
gmi_reload_key:
	pushf
	popf
	ret
.size	gmi_reload_key,.-gmi_reload_key

.globl	gmi_sm3_oneshot
.type	gmi_sm3_oneshot,\@function,3
.align	16
gmi_sm3_oneshot:
	mov %rbx, %r11 		# save rbx
	mov	%rdx,%rcx
	mov	%rdi,%rdx		# put aside %rdi
	movups	(%rdi),%xmm0		# copy-in context
	sub	\$128+8,%rsp
	movups	16(%rdi),%xmm1
	movaps	%xmm0,(%rsp)
	mov	%rsp,%rdi
	movaps	%xmm1,16(%rsp)
	mov \$0x20, %rbx
	xor	%rax,%rax
	.byte	0xf3,0x0f,0xa6,0xe8	# gm5 ccs_hash
	movaps	(%rsp),%xmm0
	movaps	16(%rsp),%xmm1
	add	\$128+8,%rsp
	movups	%xmm0,(%rdx)		# copy-out context
	movups	%xmm1,16(%rdx)
	mov %r11, %rbx		#restore rbx
	ret
.size	gmi_sm3_oneshot,.-gmi_sm3_oneshot

.globl	gmi_sm3_blocks
.type	gmi_sm3_blocks,\@function,3
.align	16
gmi_sm3_blocks:
	mov %rbx, %r11 		# save rbx
	mov	%rdx,%rcx
	mov	%rdi,%rdx		# put aside %rdi
	movups	(%rdi),%xmm0		# copy-in context
	sub	\$128+8,%rsp
	movups	16(%rdi),%xmm1
	movaps	%xmm0,(%rsp)
	mov	%rsp,%rdi
	movaps	%xmm1,16(%rsp)
	mov \$0x20, %rbx
	mov	\$-1,%rax
	.byte	0xf3,0x0f,0xa6,0xe8	# gm5 ccs_hash
	movaps	(%rsp),%xmm0
	movaps	16(%rsp),%xmm1
	add	\$128+8,%rsp
	movups	%xmm0,(%rdx)		# copy-out context
	movups	%xmm1,16(%rdx)
	mov %r11, %rbx		#restore rbx
	ret
.size	gmi_sm3_blocks,.-gmi_sm3_blocks



.globl	gmi_sm4_encrypt
.type	gmi_sm4_encrypt,\@function,4
.align	16
gmi_sm4_encrypt:

	push %rbp
	push %rbx	# save rbx
	push %rdi
	push %rsi


	lea 32(%rdx), %rbx
	shr	\$0x04, %rcx
	mov 16(%rdx), %rax
	
	.byte	0xf3,0x0f,0xa7,0xf0	# gx6 ccs_encrypt

	pop %rsi
	pop %rdi
	pop %rbx		#restore rbx
	pop %rbp
	ret
.size	gmi_sm4_encrypt,.-gmi_sm4_encrypt

.globl	gmi_sm4_ecb_enc
.type	gmi_sm4_ecb_enc,\@function,3
.align	16
gmi_sm4_ecb_enc:

	push %rbp
	push %rbx	# save rbx
	push %rdi
	push %rsi

	mov %rsi, %rax
	mov %rdi, %rsi
	mov %rax, %rdi

	mov	%rdx, %rbx
	mov	\$1, %rcx
	mov \$0x60, %rax
	
	.byte	0xf3,0x0f,0xa7,0xf0	# gx6 ccs_encrypt

	pop %rsi
	pop %rdi
	pop %rbx		#restore rbx
	pop %rbp
	ret
.size	gmi_sm4_ecb_enc,.-gmi_sm4_ecb_enc


___

$code.=<<___;
.asciz	"ZX GMI x86_64 module"
.align	16
.data
.align	8
.Lgmi_saved_context:
	.quad	0
___
$code =~ s/\`([^\`]*)\`/eval($1)/gem;

print $code;

close STDOUT;
