	.section	__TEXT,__text,regular,pure_instructions
	.macosx_version_min 10, 10
	.globl	_EVP_seed_cbc
	.align	4, 0x90
_EVP_seed_cbc:                          ## @EVP_seed_cbc
	.cfi_startproc
## BB#0:
	pushq	%rbp
Ltmp0:
	.cfi_def_cfa_offset 16
Ltmp1:
	.cfi_offset %rbp, -16
	movq	%rsp, %rbp
Ltmp2:
	.cfi_def_cfa_register %rbp
	leaq	_seed_cbc(%rip), %rax
	popq	%rbp
	retq
	.cfi_endproc

	.globl	_EVP_seed_cfb128
	.align	4, 0x90
_EVP_seed_cfb128:                       ## @EVP_seed_cfb128
	.cfi_startproc
## BB#0:
	pushq	%rbp
Ltmp3:
	.cfi_def_cfa_offset 16
Ltmp4:
	.cfi_offset %rbp, -16
	movq	%rsp, %rbp
Ltmp5:
	.cfi_def_cfa_register %rbp
	leaq	_seed_cfb128(%rip), %rax
	popq	%rbp
	retq
	.cfi_endproc

	.globl	_EVP_seed_ofb
	.align	4, 0x90
_EVP_seed_ofb:                          ## @EVP_seed_ofb
	.cfi_startproc
## BB#0:
	pushq	%rbp
Ltmp6:
	.cfi_def_cfa_offset 16
Ltmp7:
	.cfi_offset %rbp, -16
	movq	%rsp, %rbp
Ltmp8:
	.cfi_def_cfa_register %rbp
	leaq	_seed_ofb(%rip), %rax
	popq	%rbp
	retq
	.cfi_endproc

	.globl	_EVP_seed_ecb
	.align	4, 0x90
_EVP_seed_ecb:                          ## @EVP_seed_ecb
	.cfi_startproc
## BB#0:
	pushq	%rbp
Ltmp9:
	.cfi_def_cfa_offset 16
Ltmp10:
	.cfi_offset %rbp, -16
	movq	%rsp, %rbp
Ltmp11:
	.cfi_def_cfa_register %rbp
	leaq	_seed_ecb(%rip), %rax
	popq	%rbp
	retq
	.cfi_endproc

	.align	4, 0x90
_seed_init_key:                         ## @seed_init_key
	.cfi_startproc
## BB#0:
	pushq	%rbp
Ltmp12:
	.cfi_def_cfa_offset 16
Ltmp13:
	.cfi_offset %rbp, -16
	movq	%rsp, %rbp
Ltmp14:
	.cfi_def_cfa_register %rbp
	subq	$32, %rsp
	movq	%rdi, -8(%rbp)
	movq	%rsi, -16(%rbp)
	movq	%rdx, -24(%rbp)
	movl	%ecx, -28(%rbp)
	movq	-16(%rbp), %rdi
	movq	-8(%rbp), %rdx
	movq	120(%rdx), %rdx
	movq	%rdx, %rsi
	callq	_SEED_set_key
	movl	$1, %eax
	addq	$32, %rsp
	popq	%rbp
	retq
	.cfi_endproc

	.align	4, 0x90
_seed_cbc_cipher:                       ## @seed_cbc_cipher
	.cfi_startproc
## BB#0:
	pushq	%rbp
Ltmp15:
	.cfi_def_cfa_offset 16
Ltmp16:
	.cfi_offset %rbp, -16
	movq	%rsp, %rbp
Ltmp17:
	.cfi_def_cfa_register %rbp
	subq	$48, %rsp
	movq	%rdi, -8(%rbp)
	movq	%rsi, -16(%rbp)
	movq	%rdx, -24(%rbp)
	movq	%rcx, -32(%rbp)
LBB5_1:                                 ## =>This Inner Loop Header: Depth=1
	movabsq	$4611686018427387904, %rax ## imm = 0x4000000000000000
	cmpq	%rax, -32(%rbp)
	jb	LBB5_3
## BB#2:                                ##   in Loop: Header=BB5_1 Depth=1
	movabsq	$4611686018427387904, %rdx ## imm = 0x4000000000000000
	movq	-24(%rbp), %rdi
	movq	-16(%rbp), %rsi
	movq	-8(%rbp), %rax
	movq	120(%rax), %rax
	movq	-8(%rbp), %rcx
	addq	$40, %rcx
	movq	-8(%rbp), %r8
	movl	16(%r8), %r9d
	movq	%rcx, -40(%rbp)         ## 8-byte Spill
	movq	%rax, %rcx
	movq	-40(%rbp), %r8          ## 8-byte Reload
	callq	_SEED_cbc_encrypt
	movq	-32(%rbp), %rax
	movabsq	$4611686018427387904, %rcx ## imm = 0x4000000000000000
	subq	%rcx, %rax
	movq	%rax, -32(%rbp)
	movabsq	$4611686018427387904, %rax ## imm = 0x4000000000000000
	addq	-24(%rbp), %rax
	movq	%rax, -24(%rbp)
	movabsq	$4611686018427387904, %rax ## imm = 0x4000000000000000
	addq	-16(%rbp), %rax
	movq	%rax, -16(%rbp)
	jmp	LBB5_1
LBB5_3:
	cmpq	$0, -32(%rbp)
	je	LBB5_5
## BB#4:
	movq	-24(%rbp), %rdi
	movq	-16(%rbp), %rsi
	movq	-32(%rbp), %rdx
	movq	-8(%rbp), %rax
	movq	120(%rax), %rax
	movq	-8(%rbp), %rcx
	addq	$40, %rcx
	movq	-8(%rbp), %r8
	movl	16(%r8), %r9d
	movq	%rcx, -48(%rbp)         ## 8-byte Spill
	movq	%rax, %rcx
	movq	-48(%rbp), %r8          ## 8-byte Reload
	callq	_SEED_cbc_encrypt
LBB5_5:
	movl	$1, %eax
	addq	$48, %rsp
	popq	%rbp
	retq
	.cfi_endproc

	.align	4, 0x90
_seed_cfb128_cipher:                    ## @seed_cfb128_cipher
	.cfi_startproc
## BB#0:
	pushq	%rbp
Ltmp18:
	.cfi_def_cfa_offset 16
Ltmp19:
	.cfi_offset %rbp, -16
	movq	%rsp, %rbp
Ltmp20:
	.cfi_def_cfa_register %rbp
	subq	$80, %rsp
	movabsq	$4611686018427387904, %rax ## imm = 0x4000000000000000
	movq	%rdi, -8(%rbp)
	movq	%rsi, -16(%rbp)
	movq	%rdx, -24(%rbp)
	movq	%rcx, -32(%rbp)
	movq	%rax, -40(%rbp)
	movq	-32(%rbp), %rax
	cmpq	-40(%rbp), %rax
	jae	LBB6_2
## BB#1:
	movq	-32(%rbp), %rax
	movq	%rax, -40(%rbp)
LBB6_2:
	jmp	LBB6_3
LBB6_3:                                 ## =>This Inner Loop Header: Depth=1
	xorl	%eax, %eax
	movb	%al, %cl
	cmpq	$0, -32(%rbp)
	movb	%cl, -41(%rbp)          ## 1-byte Spill
	je	LBB6_5
## BB#4:                                ##   in Loop: Header=BB6_3 Depth=1
	movq	-32(%rbp), %rax
	cmpq	-40(%rbp), %rax
	setae	%cl
	movb	%cl, -41(%rbp)          ## 1-byte Spill
LBB6_5:                                 ##   in Loop: Header=BB6_3 Depth=1
	movb	-41(%rbp), %al          ## 1-byte Reload
	testb	$1, %al
	jne	LBB6_6
	jmp	LBB6_9
LBB6_6:                                 ##   in Loop: Header=BB6_3 Depth=1
	movq	-24(%rbp), %rdi
	movq	-16(%rbp), %rsi
	movq	-32(%rbp), %rdx
	movq	-8(%rbp), %rax
	movq	120(%rax), %rax
	movq	-8(%rbp), %rcx
	addq	$40, %rcx
	movq	-8(%rbp), %r8
	addq	$88, %r8
	movq	-8(%rbp), %r9
	movl	16(%r9), %r10d
	movq	%rcx, -56(%rbp)         ## 8-byte Spill
	movq	%rax, %rcx
	movq	-56(%rbp), %rax         ## 8-byte Reload
	movq	%r8, -64(%rbp)          ## 8-byte Spill
	movq	%rax, %r8
	movq	-64(%rbp), %r9          ## 8-byte Reload
	movl	%r10d, (%rsp)
	callq	_SEED_cfb128_encrypt
	movq	-40(%rbp), %rax
	movq	-32(%rbp), %rcx
	subq	%rax, %rcx
	movq	%rcx, -32(%rbp)
	movq	-40(%rbp), %rax
	addq	-24(%rbp), %rax
	movq	%rax, -24(%rbp)
	movq	-40(%rbp), %rax
	addq	-16(%rbp), %rax
	movq	%rax, -16(%rbp)
	movq	-32(%rbp), %rax
	cmpq	-40(%rbp), %rax
	jae	LBB6_8
## BB#7:                                ##   in Loop: Header=BB6_3 Depth=1
	movq	-32(%rbp), %rax
	movq	%rax, -40(%rbp)
LBB6_8:                                 ##   in Loop: Header=BB6_3 Depth=1
	jmp	LBB6_3
LBB6_9:
	movl	$1, %eax
	addq	$80, %rsp
	popq	%rbp
	retq
	.cfi_endproc

	.align	4, 0x90
_seed_ofb_cipher:                       ## @seed_ofb_cipher
	.cfi_startproc
## BB#0:
	pushq	%rbp
Ltmp21:
	.cfi_def_cfa_offset 16
Ltmp22:
	.cfi_offset %rbp, -16
	movq	%rsp, %rbp
Ltmp23:
	.cfi_def_cfa_register %rbp
	subq	$64, %rsp
	movq	%rdi, -8(%rbp)
	movq	%rsi, -16(%rbp)
	movq	%rdx, -24(%rbp)
	movq	%rcx, -32(%rbp)
LBB7_1:                                 ## =>This Inner Loop Header: Depth=1
	movabsq	$4611686018427387904, %rax ## imm = 0x4000000000000000
	cmpq	%rax, -32(%rbp)
	jb	LBB7_3
## BB#2:                                ##   in Loop: Header=BB7_1 Depth=1
	movabsq	$4611686018427387904, %rdx ## imm = 0x4000000000000000
	movq	-24(%rbp), %rdi
	movq	-16(%rbp), %rsi
	movq	-8(%rbp), %rax
	movq	120(%rax), %rax
	movq	-8(%rbp), %rcx
	addq	$40, %rcx
	movq	-8(%rbp), %r8
	addq	$88, %r8
	movq	%rcx, -40(%rbp)         ## 8-byte Spill
	movq	%rax, %rcx
	movq	-40(%rbp), %rax         ## 8-byte Reload
	movq	%r8, -48(%rbp)          ## 8-byte Spill
	movq	%rax, %r8
	movq	-48(%rbp), %r9          ## 8-byte Reload
	callq	_SEED_ofb128_encrypt
	movq	-32(%rbp), %rax
	movabsq	$4611686018427387904, %rcx ## imm = 0x4000000000000000
	subq	%rcx, %rax
	movq	%rax, -32(%rbp)
	movabsq	$4611686018427387904, %rax ## imm = 0x4000000000000000
	addq	-24(%rbp), %rax
	movq	%rax, -24(%rbp)
	movabsq	$4611686018427387904, %rax ## imm = 0x4000000000000000
	addq	-16(%rbp), %rax
	movq	%rax, -16(%rbp)
	jmp	LBB7_1
LBB7_3:
	cmpq	$0, -32(%rbp)
	je	LBB7_5
## BB#4:
	movq	-24(%rbp), %rdi
	movq	-16(%rbp), %rsi
	movq	-32(%rbp), %rdx
	movq	-8(%rbp), %rax
	movq	120(%rax), %rax
	movq	-8(%rbp), %rcx
	addq	$40, %rcx
	movq	-8(%rbp), %r8
	addq	$88, %r8
	movq	%rcx, -56(%rbp)         ## 8-byte Spill
	movq	%rax, %rcx
	movq	-56(%rbp), %rax         ## 8-byte Reload
	movq	%r8, -64(%rbp)          ## 8-byte Spill
	movq	%rax, %r8
	movq	-64(%rbp), %r9          ## 8-byte Reload
	callq	_SEED_ofb128_encrypt
LBB7_5:
	movl	$1, %eax
	addq	$64, %rsp
	popq	%rbp
	retq
	.cfi_endproc

	.align	4, 0x90
_seed_ecb_cipher:                       ## @seed_ecb_cipher
	.cfi_startproc
## BB#0:
	pushq	%rbp
Ltmp24:
	.cfi_def_cfa_offset 16
Ltmp25:
	.cfi_offset %rbp, -16
	movq	%rsp, %rbp
Ltmp26:
	.cfi_def_cfa_register %rbp
	subq	$64, %rsp
	movq	%rdi, -16(%rbp)
	movq	%rsi, -24(%rbp)
	movq	%rdx, -32(%rbp)
	movq	%rcx, -40(%rbp)
	movq	-16(%rbp), %rcx
	movq	(%rcx), %rcx
	movslq	4(%rcx), %rcx
	movq	%rcx, -56(%rbp)
	movq	-40(%rbp), %rcx
	cmpq	-56(%rbp), %rcx
	jae	LBB8_2
## BB#1:
	movl	$1, -4(%rbp)
	jmp	LBB8_7
LBB8_2:
	movq	-56(%rbp), %rax
	movq	-40(%rbp), %rcx
	subq	%rax, %rcx
	movq	%rcx, -40(%rbp)
	movq	$0, -48(%rbp)
LBB8_3:                                 ## =>This Inner Loop Header: Depth=1
	movq	-48(%rbp), %rax
	cmpq	-40(%rbp), %rax
	ja	LBB8_6
## BB#4:                                ##   in Loop: Header=BB8_3 Depth=1
	movq	-32(%rbp), %rax
	addq	-48(%rbp), %rax
	movq	-24(%rbp), %rcx
	addq	-48(%rbp), %rcx
	movq	-16(%rbp), %rdx
	movq	120(%rdx), %rdx
	movq	-16(%rbp), %rsi
	movl	16(%rsi), %edi
	movl	%edi, -60(%rbp)         ## 4-byte Spill
	movq	%rax, %rdi
	movq	%rcx, %rsi
	movl	-60(%rbp), %ecx         ## 4-byte Reload
	callq	_SEED_ecb_encrypt
## BB#5:                                ##   in Loop: Header=BB8_3 Depth=1
	movq	-56(%rbp), %rax
	addq	-48(%rbp), %rax
	movq	%rax, -48(%rbp)
	jmp	LBB8_3
LBB8_6:
	movl	$1, -4(%rbp)
LBB8_7:
	movl	-4(%rbp), %eax
	addq	$64, %rsp
	popq	%rbp
	retq
	.cfi_endproc

	.section	__DATA,__const
	.align	3                       ## @seed_cbc
_seed_cbc:
	.long	777                     ## 0x309
	.long	16                      ## 0x10
	.long	16                      ## 0x10
	.long	16                      ## 0x10
	.quad	2                       ## 0x2
	.quad	_seed_init_key
	.quad	_seed_cbc_cipher
	.quad	0
	.long	128                     ## 0x80
	.space	4
	.quad	0
	.quad	0
	.quad	0
	.quad	0

	.align	3                       ## @seed_cfb128
_seed_cfb128:
	.long	779                     ## 0x30b
	.long	1                       ## 0x1
	.long	16                      ## 0x10
	.long	16                      ## 0x10
	.quad	3                       ## 0x3
	.quad	_seed_init_key
	.quad	_seed_cfb128_cipher
	.quad	0
	.long	128                     ## 0x80
	.space	4
	.quad	0
	.quad	0
	.quad	0
	.quad	0

	.align	3                       ## @seed_ofb
_seed_ofb:
	.long	778                     ## 0x30a
	.long	1                       ## 0x1
	.long	16                      ## 0x10
	.long	16                      ## 0x10
	.quad	4                       ## 0x4
	.quad	_seed_init_key
	.quad	_seed_ofb_cipher
	.quad	0
	.long	128                     ## 0x80
	.space	4
	.quad	0
	.quad	0
	.quad	0
	.quad	0

	.align	3                       ## @seed_ecb
_seed_ecb:
	.long	776                     ## 0x308
	.long	16                      ## 0x10
	.long	16                      ## 0x10
	.long	0                       ## 0x0
	.quad	1                       ## 0x1
	.quad	_seed_init_key
	.quad	_seed_ecb_cipher
	.quad	0
	.long	128                     ## 0x80
	.space	4
	.quad	0
	.quad	0
	.quad	0
	.quad	0


.subsections_via_symbols
