//
//  KerbApp12.h
//  bifrost
//
//  Created by @its_a_feature_ on 10/14/19.
//  Copyright © 2019 Cody Thomas (@its_a_feature_). All rights reserved.
//

#import "kirbi.h"
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonHMAC.h>

@interface KerbApp12 : NSObject
/*
 Application 12 (1 elem)                                            0x6C [length bytes]
     SEQUENCE (4 elem)                                              0x30 [length bytes]
       [1] (1 elem)                                                 0xA1 [length bytes]
         INTEGER 5 (pvno) (static)                                  0x02 [length bytes] [value]
       [2] (1 elem)                                                 0xA2 [length bytes]
         INTEGER 12 (krb-tgs-req)                                   0x02 [length bytes] [value]
       [3] (1 elem)                                                 0xA3 [length bytes]
         SEQUENCE (1 elem)                                          0x30 [length bytes]          (sequence of PA_DATA elements)
           SEQUENCE (2 elem)                                        0x30 [length bytes]          ----- start of PA_DATA for normal TS-REQ
             [1] (1 elem)                                           0xA1 [length bytes]
               INTEGER 1 (krb5-padata-tgs-req)                      0x02 [lenght bytes] [value]
             [2] (1 elem)                                           0xA2 [length bytes]
               OCTET STRING (1 elem) padata-value                   0x04 [length bytes]
                 Application 14 (1 elem) ap-req (msg type)          0x6E [length bytes]
                   SEQUENCE (5 elem)                                0x30 [length bytes]
                     [0] (1 elem)                                   0xA0 [length bytes]
                       INTEGER 5 pvno (static)                      0x02 [length bytes] [value]
                     [1] (1 elem)                                   0xA1 [length bytes]
                       INTEGER 14 krb-ap-req                        0x02 [length bytes] [value]
                     [2] (1 elem)                                   0xA2 [length bytes]
                       BIT STRING (32 bit) 0 ap-options             0x03 [length bytes] [value]
                     [3] (1 elem) ticket                            0xA3 [length bytes]
                       Application 1 (1 elem)                       0x61 [length bytes]
                         SEQUENCE (4 elem)                          0x30 [length bytes]
                           [0] (1 elem)                             0xA0 [length bytes]
                             INTEGER 5 tkt-vno                      0x02 [length bytes] [value]
                           [1] (1 elem)                             0xA1 [length bytes]
                             GeneralString realm                    0x1B [length bytes] [value]
                           [2] (1 elem) sname                       0xA2 [length bytes]
                             SEQUENCE (2 elem)                      0x30 [length bytes]
                               [0] (1 elem)                         0xA0 [length bytes]
                                 INTEGER 1 krb5-nt-principal        0x02 [length bytes] [value]
                               [1] (1 elem)                         0xA1 [length bytes]
                                 SEQUENCE (2 elem)                  0x30 [length bytes]
                                   GeneralString krbtgt             0x1B [length bytes] [value]
                                   GeneralString domain.com         0x1B [length bytes] [value]
                           [3] (1 elem) enc-part                    0xA3 [length bytes]
                             SEQUENCE (3 elem)                      0x30 [length bytes]
                               [0] (1 elem)                         0xA0 [length bytes]
                                 INTEGER 18 enc-type                0x02 [length bytes] [value]
                               [1] (1 elem)                         0xA1 [length bytes]
                                 INTEGER 12 kvno                    0x02 [length bytes] [value]
                               [2] (1 elem)                         0xA2 [length bytes]
                                 OCTET STRING (1070 byte)           0x04 [length bytes] [value]
                     [4] (1 elem) authenticator                     0xA4 [length bytes]
                       SEQUENCE (2 elem)                            0x30 [length bytes]
                         [0] (1 elem)                               0xA0 [length bytes]
                           INTEGER 18 enctype                       0x02 [length bytes] [value]
                         [2] (1 elem)                               0xA2 [length bytes]
                           OCTET STRING (179 byte)                  0x04 [length bytes] [value]   ------ end of PA_DATA for normal TS-REQ
        SEQUENCE (2 elem) another padata                            0x30 [length bytes]           ------ OPTIONAL start of PADATA-FOR-USER (in S4U2Self)
            [1] (1 elem)                                            0xA1 [length bytes]
              INTEGER 129 (static krb5-padata-for-user)             0x02 [length bytes] [value]
            [2] (1 elem)                                            0xA2 [length bytes] [value]
              OCTET STRING (1 elem)                                 0x04 [length bytes]
                SEQUENCE (4 elem)                                   0x30 [length bytes]
                  [0] (1 elem)                                      0xA0 [length bytes]
                    SEQUENCE (2 elem)                               0x30 [length bytes]
                      [0] (1 elem)                                  0xA0 [length bytes]
                        INTEGER 10 ( krb5-nt-enterprise-principal)  0x02 [length bytes] [value]
                      [1] (1 elem)                                  0xA1 [length bytes]
                        SEQUENCE (1 elem)                           0x30 [length bytes]
                          GeneralString (targetuser@domain)         0x1B [length bytes] [value]
                  [1] (1 elem)                                      0xA1 [length bytes]
                    GeneralString (realm)                           0x1B [length bytes] [value]
                  [2] (1 elem)                                      0xA2 [length bytes]
                    SEQUENCE (2 elem)                               0x30 [length bytes]
                      [0] (1 elem)                                  0xA0 [length bytes]
                        INTEGER -138 (static cksumtype-hmac-md5)    0x02 [length bytes] [value]
                      [1] (1 elem)                                  0xA1 [length bytes]
                        OCTET STRING (16 byte)  (checksum value)    0x04 [length bytes] [value]
                  [3] (1 elem)                                      0xA3 [length bytes] [value]
                    GeneralString ("Kerberos" -  the auth type)     0x1B [length bytes] [value] ------- OPTIONAL end of PADATA-FOR-USER (in S4U2Self)
       [4] (1 elem) req-body                                        0xA4 [length bytes]
         SEQUENCE (6 elem)                                          0x30 [length bytes]
           [0] (1 elem)                                             0xA0 [length bytes]
             BIT STRING (32 bit) kdc-options                        0x03 [length bytes] [value]
           [1] (only for S4U2self)                                  0xA1 [length bytes]        ------- OPTIONAL start only for S4U2Self
                SEQUENCE                                            0x30 [length bytes]
                    [0]                                             0xA0 [length bytes]
                        INTEGER 1                                   0x02 [length bytes] [value]
                    [1]                                             0xA1 [length bytes]
                        SEQUENCE                                    0x30 [length bytes]
                            GeneralString username of request user  0x1B [length bytes] [value] ------- OPTIONAL end  only for S4U2Self
           [2] (1 elem)                                             0xA2 [length bytes]
             GeneralString realm (serviceDomain)                    0x1B [length bytes] [value]
           [3] (1 elem) sname                                       0xA3 [length bytes]
             SEQUENCE (2 elem)                                      0x30 [length bytes]
               [0] (1 elem)                                         0xA0 [length bytes]
                 INTEGER 3 krb5-nt-srv-hst                          0x02 [length bytes] [value] ---- note: in S4U2Self, this will be a value 1
               [1] (1 elem)                                         0xA1 [length bytes]
                 SEQUENCE (2 elem)                                  0x30 [length bytes]
                   GeneralString cifs                               0x1B [length bytes] [value] ----- note: in S4U2Self, this is only one general string of the requesting user
                   GeneralString hostname                           0x1B [length bytes] [value] ----- note: in S4U2Self, this value isn't here
           [5] (1 elem) til                                         0xA5 [length bytes]
             GeneralizedTime 1970-01-01 00:00:00 UTC                0x18 [length bytes] [value]
           [7] (1 elem)                                             0xA7 [length bytes]
             INTEGER 1227549756 nonce                               0x02 [length bytes] [value]
           [8] (1 elem)                                             0xA8 [length bytes]
             SEQUENCE (1 elem)                                      0x30 [length bytes]
               INTEGER 18 enctype                                   0x02 [length bytes] [value]
 **/
@property bool isS4U2Self;
@property bool kerberoasting;
@property bool isS4U2Proxy;
@property KerbSequence* PADATA_FOR_USER;
@property KerbSequence* PADATA_FOR_TGS;
@property KerbSequence* PADATA_OPTIONS;
@property KerbGenericString* service;
@property KerbGenericString* serviceDomain;
@property KerbGenericString* targetUser; //this is for S4U2Self only
@property KerbOctetString* key12;
@property NSData* innerTicket;
@property KerbSequence* checksumdata;
//standard TGS-REQ information, service should be like cifs/hostname.domain.com
-(id)initWithTicket:(struct Krb5Ticket*)TGT Service:(NSString*)service TargetDomain:(NSString*)targetDomain Kerberoasting:(bool)kerberoast;
//for S4U2Self
-(id)initWithTicket:(struct Krb5Ticket*)TGT TargetUser:(NSString*)targetUser TargetDomain:(NSString*)targetDomain;
//for S4U2Proxy
-(id)initForProxyWithTicket:(struct Krb5Ticket*)TGT Service:(NSString*)service TargetDomain:(NSString*)targetDomain InnerTicket:(NSData*)innerTicket;
-(NSData*)collapseToNSData;
-(ASN1_Obj*)collapseToAsnObject;
@end

