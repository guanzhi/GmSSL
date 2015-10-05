#include <string.h>
#include <openssl/bio.h>
#include "cpk.h"

int CPK_MASTER_SECRET_print(BIO *out, CPK_MASTER_SECRET *master,
	int indent, unsigned long flags)
{

	BIO_printf(out, "%s() not implemented\n", __FUNCTION__);

	return 1;
}

int CPK_PUBLIC_PARAMS_print(BIO *out, CPK_PUBLIC_PARAMS *params,
	int indent, unsigned long flags)
{
	BIO_printf(out, "%s() not implemented\n", __FUNCTION__);
	return 1;
}

