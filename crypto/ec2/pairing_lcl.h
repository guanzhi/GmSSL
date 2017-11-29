


typedef struct pairing_parameters_st {
	long version;
	ASN1_OBJECT *cid;
	ASN1_INTEGER *p;
	ASN1_INTEGER *a;
	ASN1_INTEGER *b;
	ASN1_OBJECT *beta;
	ASN1_INTEGER *cofactor;
	ASN1_INTEGER *order;
	ASN1_INTEGER *embedded_degree;
	ASN1_OCTET_STRING *G1;
	ASN1_OCTET_STRING *G2;
	ASN1_TYPE *eid;
	ASN1_INTEGER *d1;
	ASN1_INTEGER *d2;
	ANS1_OBJECT *phi;
}




