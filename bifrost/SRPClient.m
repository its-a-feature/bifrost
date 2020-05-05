//
//  SRPClient.m
//  bifrost
//
//  Created by Cody Thomas on 2/2/20.
//  Copyright © 2020 @its_a_feature_. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "SRPClient.h"

@implementation SRPClient

unsigned char* bytes_s = 0;  //salt
unsigned char* bytes_v = 0;  //verifier key
const unsigned char* bytes_A = 0;  //public A
unsigned char* bytes_B = 0;  //public B
const unsigned char* bytes_M = 0;  //computed M
int len_s   = 0;
int len_v   = 0;
int len_A   = 0;
int len_B   = 0;
int len_M   = 0;
unsigned char* bytes_HAMK = 0;
struct SRPVerifier* ver;
struct SRPUser* usr;
const unsigned char * password;
SRP_HashAlgorithm alg = SRP_SHA512;
SRP_NGType ng_type = SRP_NG_8192;
//srp_create_salted_verification_key
//void srp_create_salted_verification_key( SRP_HashAlgorithm alg,
//SRP_NGType ng_type, const char * username,
//const unsigned char * password, int len_password,
//const unsigned char ** bytes_s, int * len_s,
//const unsigned char ** bytes_v, int * len_v,
//const char * n_hex, const char * g_hex )
-(int)createVerifierUsername:(char*)username Password:(const unsigned char*)password PLen:(int)pLen Salt:(unsigned char*) salt{
    srp_create_known_salted_verification_key(SRP_SHA512, ng_type, username, password, pLen, salt, 16, &bytes_v, &len_v, 0, 0);
    printf("\n[*] Generated Verifier Key: ");
    for(int i = 0; i < len_v; i++){
        printf("%02X", bytes_v[i]);
    }
    printf("\n");
    return 0;
}
//srp_user_new, begins auth process
//srp_user_start_authentication, generates A
//srp_verifier_new,
-(int)createNewUser:(char*)username Password:(const unsigned char*)password PasswordLen:(int)password_len{
    self.usr = srp_user_new(alg, ng_type, username, password, password_len, 0, 0, 1);
    srp_user_start_authentication( self.usr, &bytes_A, &len_A );
    if(len_A == 0){return -1;}
    self.bytes_A = bytes_A;
    self.password = password;
    return 0;
}
//srp_user_proces_challenge, this generates M
-(int)processChallengeB:(const unsigned char*)B BLen:(int)bLen{
    srp_user_process_challenge( self.usr, self.bytes_s, 16, B, bLen, &bytes_M, &len_M );
    if(len_M == 0){return -1;}
    self.bytes_M = bytes_M;
    self.len_M = len_M;
    return 0;
}
//srp_verifier_verify_session, generates HAMK (server side piece)
//srp_user_verify_session, takes in HAMK from server to get key
-(int)verifySessionHAMK:(char*) HAMK{
    srp_user_verify_session( self.usr, HAMK );
    if( !srp_user_is_authenticated(self.usr)){
        printf("[-] Failed to authenticate\n");
        return -1;
    }else{
        printf("[+] Successfully authenticated\n");
        return 0;
    }
}
-(unsigned char*) getSessionKey{
    int key_len = srp_user_get_session_key_length( self.usr );
    //printf("\nKey len: %d\n", key_len);
    unsigned char* key = srp_user_get_session_key( self.usr, &key_len );
    //printf("\n[*] Generated Session Key: ");
    //for(int i = 0; i < key_len; i++){
    //    printf("%02X", key[i]);
    //}
    //printf("\n");
    return key;
}
-(int) getSessionKeyLength{
    return srp_user_get_session_key_length( self.usr );
}
@end
