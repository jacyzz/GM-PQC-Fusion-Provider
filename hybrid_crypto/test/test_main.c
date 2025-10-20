#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <oqs/oqs.h>
#include "../include/hybrid_kex.h"
#include "../include/hybrid_sig.h"

int main() {
    OQS_init();
    printf("Testing Hybrid Key Exchange (SM2+ML-KEM)...)\n");
    uint8_t *c_pub=NULL,*c_priv=NULL; size_t c_pub_len=0,c_priv_len=0;
    uint8_t *s_pub=NULL,*s_priv=NULL; size_t s_pub_len=0,s_priv_len=0;
    assert(hybrid_kex_keygen(&c_pub,&c_pub_len,&c_priv,&c_priv_len)==0);
    assert(hybrid_kex_keygen(&s_pub,&s_pub_len,&s_priv,&s_priv_len)==0);
    uint8_t *srv_shared=NULL; size_t srv_shared_len=0; uint8_t *resp=NULL; size_t resp_len=0;
    assert(hybrid_kex_server_derive(&srv_shared,&srv_shared_len,&resp,&resp_len,c_pub,c_pub_len,s_priv,s_priv_len)==0);
    uint8_t *cli_shared=NULL; size_t cli_shared_len=0;
    assert(hybrid_kex_client_derive(&cli_shared,&cli_shared_len,resp,resp_len,c_priv,c_priv_len)==0);
    assert(srv_shared_len==cli_shared_len && memcmp(srv_shared,cli_shared,srv_shared_len)==0);
    printf("KEX test PASSED.\n");

    printf("Testing Composite Signature (SM2+ML-DSA)...)\n");
    uint8_t *sig_pub=NULL,*sig_priv=NULL; size_t sig_pub_len=0,sig_priv_len=0;
    assert(hybrid_sig_keygen(&sig_pub,&sig_pub_len,&sig_priv,&sig_priv_len)==0);
    uint8_t msg[32]; for (int i=0;i<32;i++) msg[i]=(uint8_t)i; // pretend it's an SM3 digest
    uint8_t *sig=NULL; size_t sig_len=0;
    assert(hybrid_sig_sign(&sig,&sig_len,msg,sizeof msg,sig_priv,sig_priv_len)==0);
    assert(hybrid_sig_verify(sig,sig_len,msg,sizeof msg,sig_pub,sig_pub_len)==0);
    printf("Signature test PASSED.\n");

    free(c_pub); free(c_priv); free(s_pub); free(s_priv);
    free(srv_shared); free(resp); free(cli_shared);
    free(sig_pub); free(sig_priv); free(sig);
    OQS_destroy();
    return 0;
}


