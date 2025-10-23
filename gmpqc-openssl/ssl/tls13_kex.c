# define TLS_GROUP_ID_X448_MLKEM1024 0x4F52
# define TLS_GROUP_NAME_X448_MLKEM1024 "x448_mlkem1024"

# define TLS_GROUP_ID_SM2_MLKEM768 0xFE00 /* private use */
# define TLS_GROUP_NAME_SM2_MLKEM768 "sm2_mlkem768"

typedef struct {
    unsigned int group_id;
    const char *group_name;
    int nid;
    const char *kem_alg_name;
} TLS_GROUP_INFO;

TLS_GROUP_INFO tls_group_info[] = {
    { TLS_GROUP_ID_X448_MLKEM1024, TLS_GROUP_NAME_X448_MLKEM1024, NID_undef, OQS_KEM_alg_x448_mlkem1024 },
#endif
    { TLS_GROUP_ID_SM2_MLKEM768, TLS_GROUP_NAME_SM2_MLKEM768, NID_undef, OQS_KEM_alg_sm2_mlkem768 },
    { 0, NULL, NID_undef, NULL }
};
