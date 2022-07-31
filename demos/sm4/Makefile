all:
	cc sm4_demo.c -lgmssl -o sm4_demo
	cc sm4_cbc_demo.c -lgmssl -o sm4_cbc_demo
	cc sm4_cbc_padding_demo.c -lgmssl -o sm4_cbc_padding_demo
	cc sm4_ctr_demo.c -lgmssl -o sm4_ctr_demo
	cc sm4_gcm_demo.c -lgmssl -o sm4_gcm_demo
	cc sm4_cbc_encrypt_update_demo.c -lgmssl -o sm4_cbc_encrypt_update_demo
	cc sm4_cbc_decrypt_update_demo.c -lgmssl -o sm4_cbc_decrypt_update_demo
	cc sm4_ctr_encrypt_update_demo.c -lgmssl -o sm4_ctr_encrypt_update_demo
	cc sm4_ctr_encrypt_update_demo.c -lgmssl -o sm4_ctr_decrypt_update_demo

clean:
	rm -fr sm4_demo
	rm -fr sm4_cbc_demo
	rm -fr sm4_cbc_padding_demo
	rm -fr sm4_ctr_demo
	rm -fr sm4_gcm_demo
	rm -fr sm4_cbc_encrypt_update_demo
	rm -fr sm4_cbc_decrypt_update_demo
	rm -fr sm4_ctr_encrypt_update_demo
	rm -fr sm4_ctr_decrypt_update_demo

