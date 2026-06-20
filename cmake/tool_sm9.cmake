include("${CMAKE_CURRENT_LIST_DIR}/tool_helpers.cmake")

set(SM9_PASS P@ssw0rd)
set(SM9_USER_PASS 123456)
set(SM9_ID Alice)
set(SM9_TEXT "SM9 command line test message")

file(WRITE tool_sm9_message.txt "${SM9_TEXT}")

gmssl_run(sm9setup -alg sm9sign -pass ${SM9_PASS}
	-out tool_sm9_sign_msk.pem -pubout tool_sm9_sign_mpk.pem)
gmssl_run(sm9keygen -alg sm9sign
	-in tool_sm9_sign_msk.pem -inpass ${SM9_PASS}
	-id ${SM9_ID}
	-out tool_sm9_sign_key.pem -outpass ${SM9_USER_PASS})
gmssl_run(sm9sign -key tool_sm9_sign_key.pem -pass ${SM9_USER_PASS}
	-in tool_sm9_message.txt -out tool_sm9.sig)
gmssl_run(sm9verify -pubmaster tool_sm9_sign_mpk.pem -id ${SM9_ID}
	-in tool_sm9_message.txt -sig tool_sm9.sig)

gmssl_run(sm9setup -alg sm9encrypt -pass ${SM9_PASS}
	-out tool_sm9_enc_msk.pem -pubout tool_sm9_enc_mpk.pem)
gmssl_run(sm9keygen -alg sm9encrypt
	-in tool_sm9_enc_msk.pem -inpass ${SM9_PASS}
	-id ${SM9_ID}
	-out tool_sm9_enc_key.pem -outpass ${SM9_USER_PASS})
gmssl_run(sm9encrypt -pubmaster tool_sm9_enc_mpk.pem -id ${SM9_ID}
	-in tool_sm9_message.txt -out tool_sm9_cipher.der)
gmssl_run(sm9decrypt -key tool_sm9_enc_key.pem -pass ${SM9_USER_PASS} -id ${SM9_ID}
	-in tool_sm9_cipher.der -out tool_sm9_plain.txt)
gmssl_expect_file_text(tool_sm9_plain.txt "${SM9_TEXT}")
