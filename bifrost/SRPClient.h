//
//  SRPClient.h
//  bifrost
//
//  Created by Cody Thomas on 2/2/20.
//  Copyright © 2020 @its_a_feature_. All rights reserved.
//

#ifndef SRPClient_h
#define SRPClient_h
#import "srp.h"

@interface SRPClient : NSObject

@property unsigned char* bytes_s;  //salt
@property unsigned char* bytes_v;  //verifier key
@property const unsigned char* bytes_A;  //public A
@property unsigned char* bytes_B;  //public B
@property const unsigned char* bytes_M;  //computed M
@property unsigned char* bytes_HAMK;
@property int len_M;
@property int len_s;
@property const unsigned char* password;
@property int iterations;
@property struct SRPVerifier* ver;
@property struct SRPUser* usr;

//srp_user_new, begins auth process
//srp_user_start_authentication, generates A
//srp_verifier_new,
-(int)createVerifierUsername:(char*)username Password:(const unsigned char*)password PLen:(int)pLen Salt:(unsigned char*) salt;
-(int)createNewUser:(char*)username Password:(const unsigned char*)password PasswordLen:(int)password_len;
//srp_user_proces_challenge, this generates M
-(int)processChallengeB:(const unsigned char*)B BLen:(int)bLen;
//srp_verifier_verify_session, generates HAMK (server side piece)
//srp_user_verify_session, takes in HAMK from server to get key
-(int)verifySessionHAMK:(char*)HAMK;
-(unsigned char*) getSessionKey;
-(int) getSessionKeyLength;

@end

#endif /* SRPClient_h */
