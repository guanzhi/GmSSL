#!/usr/bin/env perl

# ====================================================================
# Written by Yun Shen <yunshen@via-alliance.com> and 
# Kai Li <kelvinkli@via-alliance.com>, and refer to the code 
# written by Andy Polyakov <appro@openssl.org> for the OpenSSL
# project. The module is, however, dual licensed under OpenSSL and
# CRYPTOGAMS licenses depending on where you obtain it. For further
# details see http://www.openssl.org/~appro/cryptogams/.
# ====================================================================

# ====================================================================
# Copyright 2016 Shanghai Zhaoxin Semiconductor Co., Ltd. ALL RIGHTS RESERVED.
# ====================================================================


$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
push(@INC,"${dir}","${dir}../../crypto/perlasm");
require "x86asm.pl";

&asm_init($ARGV[0],$0);

%PADLOCK_PREFETCH=(ecb=>128, cbc=>64);	# prefetch errata
$PADLOCK_CHUNK=512;	# Must be a power of 2 larger than 16

$ctx="edx";
$out="edi";
$inp="esi";
$len="ecx";
$chunk="ebx";


&function_begin_B("zx_gmi_capability");
	&push	("ebx");
	&pushf	();
	&pop	("eax");
	&mov	("ecx","eax");
	&xor	("eax",1<<21);
	&push	("eax");
	&popf	();
	&pushf	();
	&pop	("eax");
	&xor	("ecx","eax");
	&xor	("eax","eax");
	&bt	("ecx",21);
	&jnc	(&label("zx_noluck"));
	&cpuid	();
	&xor	("eax","eax");
	&cmp	("ebx","0x".unpack("H*",'hS  '));
	&jne	(&label("zx_noluck"));
	&cmp	("edx","0x".unpack("H*",'hgna'));
	&jne	(&label("zx_noluck"));
	&cmp	("ecx","0x".unpack("H*",'  ia'));
	&jne	(&label("zx_noluck"));
	&mov	("eax",0xC0000000);
	&cpuid	();
	&mov	("edx","eax");
	&xor	("eax","eax");
	&cmp	("edx",0xC0000001);
	&jb	(&label("zx_noluck"));
	&mov	("eax",1);
	&cpuid	();
	&or	("eax",0x0f);
	&xor	("ebx","ebx");
	&and	("eax",0x0fff);
	&cmp	("eax",0x06ff);		# check for Nano
	&sete	("bl");
	&mov	("eax",0xC0000001);
	&push	("ebx");
	&cpuid	();
	&pop	("ebx");
	&mov	("eax","edx");
	&shl	("ebx",4);		# bit#4 denotes Nano
	&and	("eax",0xffffffef);
	&or	("eax","ebx")
&set_label("zx_noluck");
	&pop	("ebx");
	&ret	();
&function_end_B("zx_gmi_capability")

&function_begin_B("gmi_reload_key");
	&pushf	();
	&popf	();
	&ret	();
&function_end_B("gmi_reload_key");

&function_begin_B("gmi_xstore");
	&push	("edi");
	&mov	("edi",&wparam(0));
	&mov	("edx",&wparam(1));
	&data_byte(0x0f,0xa7,0xc0);		# xstore
	&pop	("edi");
	&ret	();
&function_end_B("gmi_xstore");

&function_begin_B("_win32_segv_handler");
	&mov	("eax",1);			# ExceptionContinueSearch
	&mov	("edx",&wparam(0));		# *ExceptionRecord
	&mov	("ecx",&wparam(2));		# *ContextRecord
	&cmp	(&DWP(0,"edx"),0xC0000005)	# ExceptionRecord->ExceptionCode == STATUS_ACCESS_VIOLATION
	&jne	(&label("ret"));
	&add	(&DWP(184,"ecx"),4);		# skip over rep sha*
	&mov	("eax",0);			# ExceptionContinueExecution
&set_label("ret");
	&ret	();
&function_end_B("_win32_segv_handler");
&safeseh("_win32_segv_handler")			if ($::win32);


&function_begin_B("gmi_sm3_oneshot");
	&push	("ebx");
	&push	("edi");
	&push	("esi");
	&xor	("eax","eax");
	&mov	("edi",&wparam(0));
	&mov	("esi",&wparam(1));
	&mov	("ecx",&wparam(2));
    if ($::win32 or $::coff) {
    	&push	(&::islabel("_win32_segv_handler"));
	&data_byte(0x64,0xff,0x30);		# push	%fs:(%eax)
	&data_byte(0x64,0x89,0x20);		# mov	%esp,%fs:(%eax)
    }
	&mov	("edx","esp");			# put aside %esp
	&add	("esp",-128);
	&movups	("xmm0",&QWP(0,"edi"));		# copy-in context
	&and	("esp",-16);
	&movups	("xmm1",&QWP(16,"edi"));
	&movaps	(&QWP(0,"esp"),"xmm0");
	&mov	("edi","esp");
	&movaps	(&QWP(16,"esp"),"xmm1");
	&mov	("ebx", 0x20);
	&xor	("eax","eax");
	&data_byte(0xf3,0x0f,0xa6,0xe8);	# gm5 ccs_hash
	&movaps	("xmm0",&QWP(0,"esp"));
	&movaps	("xmm1",&QWP(16,"esp"));
	&mov	("esp","edx");			# restore %esp
    if ($::win32 or $::coff) {
	&data_byte(0x64,0x8f,0x05,0,0,0,0);	# pop	%fs:0
	&lea	("esp",&DWP(4,"esp"));
    }
	&mov	("edi",&wparam(0));
	&movups	(&QWP(0,"edi"),"xmm0");		# copy-out context
	&movups	(&QWP(16,"edi"),"xmm1");
	&pop	("esi");
	&pop	("edi");
	&pop	("ebx");
	&ret	();
&function_end_B("gmi_sm3_oneshot");

&function_begin_B("gmi_sm3_blocks");
	&push	("ebx");
	&push	("edi");
	&push	("esi");
	&mov	("edi",&wparam(0));
	&mov	("esi",&wparam(1));
	&mov	("ecx",&wparam(2));
	&mov	("edx","esp");			# put aside %esp
	&add	("esp",-128);
	&movups	("xmm0",&QWP(0,"edi"));		# copy-in context
	&and	("esp",-16);
	&movups	("xmm1",&QWP(16,"edi"));
	&movaps	(&QWP(0,"esp"),"xmm0");
	&mov	("edi","esp");
	&movaps	(&QWP(16,"esp"),"xmm1");
	&mov	("ebx", 0x20);
	&mov	("eax",-1);
	&data_byte(0xf3,0x0f,0xa6,0xe8);	# gm5 ccs_hash
	&movaps	("xmm0",&QWP(0,"esp"));
	&movaps	("xmm1",&QWP(16,"esp"));
	&mov	("esp","edx");			# restore %esp
	&mov	("edi",&wparam(0));
	&movups	(&QWP(0,"edi"),"xmm0");		# copy-out context
	&movups	(&QWP(16,"edi"),"xmm1");
	&pop	("esi");
	&pop	("edi");
	&pop	("ebx");
	&ret	();
&function_end_B("gmi_sm3_blocks");


&function_begin_B("gmi_sm4_encrypt");

	&push	("ebx");
	&push	("edi");
	&push	("esi");
	&mov	("edi",&wparam(0));
	&mov	("esi",&wparam(1));
	&mov	("edx",&wparam(2));
	&mov	("ecx",&wparam(3));


	&lea	("ebx",&DWP(32,"edx"));
	&shr	("ecx", 4);
	&mov	("eax",&DWP(16,"edx"));

	&data_byte(0xf3,0x0f,0xa7,0xf0);	# gx6 ccs_encrypt

	&pop	("esi");
	&pop	("edi");
	&pop	("ebx");
	&ret	();
&function_end_B("gmi_sm4_encrypt");

&function_begin_B("gmi_sm4_ecb_enc");

	&push	("ebx");
	&push	("edi");
	&push	("esi");
	&mov	("esi",&wparam(0));
	&mov	("edi",&wparam(1));
	&mov	("ebx",&wparam(2));

	&mov 	("ecx", 1);
	&mov 	("eax", 0x60);
	
	&data_byte(0xf3,0x0f,0xa7,0xf0);	# gx6 ccs_encrypt

	&pop	("esi");
	&pop	("edi");
	&pop	("ebx");
	&ret	();
&function_end_B("gmi_sm4_ecb_enc");


&asciz	("ZX GMI x86 module");
&align	(16);

&dataseg();
# Essentially this variable belongs in thread local storage.
# Having this variable global on the other hand can only cause
# few bogus key reloads [if any at all on signle-CPU system],
# so we accept the penalty...
&set_label("gmi_saved_context",4);
&data_word(0);

&asm_finish();
