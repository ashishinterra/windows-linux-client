
/*
 * sscep -- Simple SCEP client implementation
 * Copyright (c) Jarkko Turkulainen 2003. All rights reserved.
 * See the file COPYRIGHT for licensing information.
 */


int i2d_pkcs7_issuer_and_subject_bio(BIO* bp, pkcs7_issuer_and_subject * ias);
int i2d_PKCS7_ISSUER_AND_SERIAL_bio(BIO* bp, PKCS7_ISSUER_AND_SERIAL * ias);

/* Routines */
int i2d_pkcs7_issuer_and_subject(pkcs7_issuer_and_subject *, unsigned char **);
pkcs7_issuer_and_subject *
d2i_pkcs7_issuer_and_subject(pkcs7_issuer_and_subject **, unsigned char **,
	long length);
pkcs7_issuer_and_subject *pkcs7_issuer_and_subject_new(void);
void pkcs7_issuer_and_subject_free(pkcs7_issuer_and_subject *);


