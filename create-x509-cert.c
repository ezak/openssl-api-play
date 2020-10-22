//
// Created by izak on 10/22/20.
//



#include <stdio.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

void generate_x509()
{

    /*generate key pair section*/
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey) {
        printf("Unable to create EVP_PKEY structure.\n");
        return;
    }

    RSA * rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
    if(!EVP_PKEY_assign_RSA(pkey, rsa))
    {
        printf("Unable to generate 2048-bit RSA key.\n");
        EVP_PKEY_free(pkey);
        return;
    }

    /* Write pkey to file */
    FILE * pkey_file = fopen("key.pem", "wb");

    if(!pkey_file) {
        printf("Unable to open \"key.pem\" for writing.\n");
        return;
    }

    if (!PEM_write_PrivateKey(pkey_file, pkey, NULL, NULL, 0, NULL, NULL)) {
        printf("Unable to write private key to disk.\n");
        fclose(pkey_file);
    }


    /* Allocate memory for the X509 structure. */
    X509 * x509 = X509_new();
    if(!x509)
    {
        printf("Unable to create X509 structure.\n");
        return;
    }

    /* Set the serial number. */
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);

    /* This certificate is valid from now until exactly one year from now. */
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);

    /* Set the public key for our certificate. */
    X509_set_pubkey(x509, pkey);

    /* We want to copy the subject name to the issuer name. */
    X509_NAME * name = X509_get_subject_name(x509);

    /* Set the country code and common name. */
    X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC, (unsigned char *)"CA",        -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC, (unsigned char *)"MyCompany", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"localhost", -1, -1, 0);

    /* Now set the issuer name. */
    X509_set_issuer_name(x509, name);

    /* Actually sign the certificate with our key. */
    if(!X509_sign(x509, pkey, EVP_sha1()))
    {
        printf("Error signing certificate.\n");
        X509_free(x509);
        return;
    }


    /* Write cert to file */
    FILE * x509_file = fopen("cert.pem", "wb");
    if(!x509_file) {
        printf("Unable to open \"cert.pem\" for writing.\n");
        return;
    }

    if (!PEM_write_X509(x509_file, x509)) {
        fclose(x509_file);
        printf("Unable to write certificate to disk.\n");
        return;
    }
}

void get_x509_fingerprint()
{
    unsigned char fingerprint[EVP_MAX_MD_SIZE];
    unsigned int finger_print_size;
    const EVP_MD *fingerprint_type = NULL;
    X509 *cert = NULL;
    BIO* bio_cert_file = NULL;

    X509 *x509 = X509_new();
    if (!x509) {
        printf("Unable to create X509 structure.\n");
        return;
    }

    FILE * x509_file = fopen("./cert.pem", "rb");
    if(!x509_file) {
        printf("Unable to open \"cert.pem\" for reading.\n");
        return;
    }

    PEM_read_X509(x509_file, &x509, 0, NULL);

    fingerprint_type = EVP_sha1();

    if (!X509_digest(x509, fingerprint_type, fingerprint, &finger_print_size)){
        printf("Error creating the certificate fingerprint.\n");
        return;
    }

    for (int j=0; j<finger_print_size; ++j)
        printf("%02x ", fingerprint[j]);

    printf("\n%s\n", fingerprint);

    printf("\n success \n");

}

int main()
{
    const char * cert_file = "./cert.pem";

    if(access(cert_file, F_OK) == -1) {
        generate_x509();
    }

    get_x509_fingerprint();

}



