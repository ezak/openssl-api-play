#include <stdio.h>

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <slcurses.h>

#include <openssl/bio.h>
#include <openssl/err.h>


/* Generates a 2048-bit RSA key. */
EVP_PKEY * generate_key()
{
    /* Allocate memory for the EVP_PKEY structure. */
    EVP_PKEY * pkey = EVP_PKEY_new();
    if(!pkey)
    {
        printf("Unable to create EVP_PKEY structure.\n");
        return NULL;
    }
    
    /* Generate the RSA key and assign it to pkey. */
    RSA * rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
    if(!EVP_PKEY_assign_RSA(pkey, rsa))
    {
        printf("Unable to generate 2048-bit RSA key.\n");
        EVP_PKEY_free(pkey);
        return NULL;
    }
    
    /* The key has been generated, return it. */
    return pkey;
}

/* Generates a self-signed x509 certificate. */
X509 * generate_x509(EVP_PKEY * pkey)
{
    /* Allocate memory for the X509 structure. */
    X509 * x509 = X509_new();
    if(!x509)
    {
        printf("Unable to create X509 structure.\n");
        return NULL;
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
        return NULL;
    }
    
    return x509;
}

/* Write certificate to disk. */
bool write_to_disk(EVP_PKEY * pkey, X509 * x509)
{
    /* Open the PEM file for writing the key to disk. */
    FILE * pkey_file = fopen("key.pem", "wb");
    if(!pkey_file)
    {
        printf("Unable to open \"key.pem\" for writing.\n");
        return 0;
    }
    
    /* Write the key to disk. */
    bool ret = PEM_write_PrivateKey(pkey_file, pkey, NULL, NULL, 0, NULL, NULL);
    fclose(pkey_file);
    
    if(!ret)
    {
        printf("Unable to write private key to disk.\n");
        return 0;
    }
    
    /* Open the PEM file for writing the certificate to disk. */
    FILE * x509_file = fopen("cert.pem", "wb");
    if(!x509_file)
    {
        printf("Unable to open \"cert.pem\" for writing.\n");
        return 0;
    }
    
    /* Write the certificate to disk. */
    ret = PEM_write_X509(x509_file, x509);
    fclose(x509_file);
    
    if(!ret)
    {
        printf("Unable to write certificate to disk.\n");
        return 0;
    }
    
    return 1;
}

/* Extract Serial Number the certificate */
unsigned char* fingerprint_hash_x509() {
    const char cert_filestr[] = "./cert.pem";
    BIO *certbio = NULL, *outbio = NULL;
    X509 *cert = NULL;
    const EVP_MD *fprint_type = NULL;
    int ret, j, fprint_size;
    unsigned char fprint[EVP_MAX_MD_SIZE];
    unsigned char *fingerprint;
    /* These function calls initialize openssl for correct work. */
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();



     /* Create the Input/Output BIO's. */
    certbio = BIO_new(BIO_s_file());
    outbio  = BIO_new_fp(stdout, BIO_NOCLOSE);

    ret = BIO_read_filename(certbio, cert_filestr);
    if (! (cert = PEM_read_bio_X509(certbio, NULL, 0, NULL))) {
        BIO_printf(outbio, "Error loading cert into memory\n");
        exit(-1);
    }


    fprint_type = EVP_sha1();

    if (!X509_digest(cert, fprint_type, fprint, &fprint_size))
        BIO_printf(outbio,"Error creating the certificate fingerprint.\n");

    //BIO_printf(outbio,"Fingerprint Method: %s\n", OBJ_nid2sn(EVP_MD_type(fprint_type)));

    //BIO_printf(outbio,"Fingerprint Length: %d\n", fprint_size);


    //BIO_printf(outbio,"Fingerprint String: ");
    for (j=0; j<fprint_size; ++j) BIO_printf(outbio, "%02x ", fprint[j]);
    //BIO_printf(outbio,"\n");

    /* OpenSSL fingerprint-style: uppercase hex bytes with colon */
    //for (j=0; j<fprint_size; j++) {
    //  BIO_printf(outbio,"%02X%c", fprint[j], (j+1 == fprint_size) ?'\n':':');
    //}

    fingerprint = (unsigned char *)outbio;


    X509_free(cert);
    BIO_free_all(certbio);
    BIO_free_all(outbio);

    return fingerprint;

}

/* Main program entry. */
int main(int argc, char ** argv)
{
    /* Generate the key. */
    printf("Generating RSA key...\n");
    
    EVP_PKEY * pkey = generate_key();
    if(!pkey)
        return 1;
    
    /* Generate the certificate. */
    printf("Generating x509 certificate...\n");
    
    X509 * x509 = generate_x509(pkey);
    if(!x509)
    {
        EVP_PKEY_free(pkey);
        return 1;
    }
    
    /* Write the private key and certificate out to disk. */
    printf("Writing key and certificate to disk...\n");
    
    int ret = write_to_disk(pkey, x509);
    EVP_PKEY_free(pkey);
    X509_free(x509);

    BIO *out = (BIO *)fingerprint_hash_x509();

    BIO_printf(out, "\n");

    if(ret)
    {
        printf("\nSuccess!\n");
        return 0;
    }
    else
        return 1;
}
