// xchg2.c
// Andrew Prudhomme
// A05419855
// cse 127 Fall 14
// Assignment 4
//

#include <stdarg.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

#include "common.h"
// hacky
#include "common.c"

const char * USAGE = "xchg2 CA_CERT LOCAL_CERT PRIVATE_KEY HOST:PORT CHAR";

int main(int argc, char * const argv[])
{
    // Command-line arguments.
    
    char * ca_cert_path;
    char * local_cert_path;
    char * private_key_path;
    char * remote_name;
    char * to_send_byte_str;
    
    // Other local variables.
    
    char to_send_byte;
    char received_byte;

    SSL_CTX * ssl_ctx;
    SSL * ssl;
    BIO * bio_ssl;
    
    // Initialize SSL library.
    
    SSL_library_init();
    SSL_load_error_strings();
        
    // Copy command-line arguments to local variables.    
    
    //if (argc != 6)
    //    usage_error_exit();
        
    //ca_cert_path = argv[1];
    //local_cert_path = argv[2];
    //private_key_path = argv[3];
    //remote_name = argv[4];
    //to_send_byte_str = argv[5];
    //to_send_byte = to_send_byte_str[0];
    local_cert_path = "client.crt";
    private_key_path = "client.key";
    remote_name = "localhost:4433";
    to_send_byte_str = "j";
   
    if(argc > 1)
    {
        remote_name = argv[1];
    }
 
    //if (!isprint(to_send_byte) || to_send_byte_str[1] != '\0')
    //    usage_error_exit();

    // create ssl context
    //if(!(ssl_ctx = SSL_CTX_new(SSLv23_method())))
    if(!(ssl_ctx = SSL_CTX_new(TLSv1_method())))
    {
        ssl_error_exit(NULL);
    }

    // add local cert to context
    if(SSL_CTX_use_certificate_chain_file(ssl_ctx,local_cert_path) != 1)
    {
        ssl_error_exit("use_certificate_chain_file failed");
    }

    // add local key to context
    if(SSL_CTX_use_PrivateKey_file(ssl_ctx,private_key_path,SSL_FILETYPE_PEM) != 1)
    {
        ssl_error_exit("use_PrivateKey_file failed");
    }

    // set CA
    //if(SSL_CTX_load_verify_locations(ssl_ctx,ca_cert_path,NULL) != 1)
    //{
    //    ssl_error_exit("load_verify_locations failed");
    //}

    // require peer to provide a cert
    //SSL_CTX_set_verify(ssl_ctx,SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,NULL);

    // establish tcp connection
    bio_ssl = BIO_new_connect(remote_name);
    if(!bio_ssl)
    {
        ssl_error_exit(NULL);
    }

    if(BIO_do_connect(bio_ssl) != 1)
    {
        ssl_error_exit(NULL);
    }
    
    // set ssl to use tcp connection
    ssl = SSL_new(ssl_ctx);
    SSL_set_bio(ssl,bio_ssl,bio_ssl);

    const char* const PREFERRED_CIPHERS = "AES128-SHA";
    SSL_set_cipher_list(ssl, PREFERRED_CIPHERS);

    // attemp ssl handshake
    if(SSL_connect(ssl) <= 0)
    {
        ssl_error_exit("SSL_connect failed");
    }

    // check for problem with cert verification
    //int result = SSL_get_verify_result(ssl);
    //if(result != X509_V_OK)
    //{
    //    ssl_error_exit("verify_result failed with %d",result);
    //}

    // confirm peer provided a cert
    X509 * servercert = SSL_get_peer_certificate(ssl);
    if(!servercert)
    {
        ssl_error_exit("server did not provide cert");
    }
    X509_free(servercert);

    // send/recv byte using ssl connection
    if(SSL_write(ssl, &to_send_byte_str[0], 1) <= 0)
    {
        ssl_error_exit("SSL_write failed");
    }
    
    if(SSL_read(ssl, &received_byte, 1) <= 0)
    {
        ssl_error_exit("SSL_read failed");
    }
    
    // output returned byte
    if(isprint(received_byte)) 
    {
        putchar(received_byte);
        putchar('\n');
    } 
    else
    {
        fprintf(stderr, "Non-printing byte 0x%02x received\n", received_byte);
    }
    
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ssl_ctx);

    exit(EXIT_SUCCESS);
}
