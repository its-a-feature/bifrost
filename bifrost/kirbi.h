//
//  kirbi.h
//  bifrost
//
//  Created by @its_a_feature_ on 10/14/19.
//  Copyright © 2019 Cody Thomas (@its_a_feature_). All rights reserved.
//
#import "asn1.h"
#import <Kerberos/Kerberos.h>
#import "KerbInteger.h"
#import "KerbOctetString.h"
#import "KerbGenericString.h"
#import "KerbBitString.h"
#import "KerbGeneralizedTime.h"
#import "KerbSequence.h"
#import "KerbCNamePrincipal.h"
#import "KerbSNamePrincipal.h"
#import "KerbApp1.h"
#import "KerbApp29.h"
#import "KerbApp12.h"

/* AS-REQ
 Application 22 (0x76), few bytes of size
    Sequence (0x30), few bytes of size
        [0] 0xA0, byte of size
            Integer (0x02), byte length of value, value (val 5)
        [1] 0xA1, byte of size
            Integer (0x02), byte length of value, value (val 22)
        [2] 0xA2, few bytes of size
            Sequence (0x30), few bytes of size
                Appliation 1 (0x61) this is the structure of the ticket saved from the krb5 api calls
        [3] 0xA3, few bytes of size
            Sequence (0x30) few bytes of size
                [0] 0xA0, byte of size
                    Integer (0x02) byte of size, value (val 0)
                [2] 0xA2, bytes of size
                    Octet String (0x04) bytes of size
                        Application 29 (0x7D), bytes of size
                            Sequence (0x30), bytes of size
                                [0] (0xA0), bytes of size
                                    Sequence (0x30), bytes of size
                                        Sequence (0x30), bytes of size
                                            [0] (0xA0), bytes of size
                                                Sequence (0x30), bytes of size
                                                    [0] (0xA0), bytesof size
                                                        Integer (0x02), enctype (val 18)
                                                    [1] (0xA1), bytes of size
                                                        Octet String (0x04), bytes of size, string (val key)
                                            [1] (0xA1), bytes of size
                                                General String (0x1B), bytes of size, string (realm)
                                            [2] (0xA2), bytes of size
                                                Sequence (0x30), bytes of size
                                                    [0] (0xA0), bytes of size
                                                        Integer (0x02), bytes of size, int (val 1)
                                                    [1] (0xA1), bytes of size
                                                        Sequence (0x30), bytes of size
                                                        General String (0x1B), bytes of size, string username
                                            [3] (0xA3), bytes of size
                                                Bit String (0x03), bytes of size (32bit), value (val ticket flags)
                                            [5] (0xA5), bytes of size
                                                Generalized Time (0x18), bytes of size, time value
                                            [6] (0xA6), bytes of size
                                                Generalized Time (0x18), bytes of size, time value
                                            [7] (0xA7), bytes of size
                                                Generalized Time (0x18), bytes of size, time value
                                            [8] (0xA8), bytes of size
                                                General String (0x1B), bytes of size, string (val realm)
                                            [9] (0xA9), bytes of size
                                                Sequence (0x30), bytes of size
                                                    [0] (0xA0) bytes of size
                                                        Integer (0x02), bytes of size, int
                                                    [1] (0xA1) bytes of size
                                                        Sequence (0x30), bytes of size
                                                            General String (0x1B), bytes of size, string (val krbtgt)
                                                            General String (0x1B), bytes of size, string (val realm)
 */
typedef struct Krb5Ticket{
    KerbApp1* app1;
    KerbApp29* app29;
} Krb5Ticket;
NSString* describeFlags(int flag);
NSData* createKirbi(Krb5Ticket krb_cred);
NSString* describeTicket(Krb5Ticket ticket);
Krb5Ticket parseKirbi(NSData* data);
NSData* createPADataTimestamp(void);
NSData* createPADataASReq(int enctype, NSString* hash, NSArray* PADATATypes, NSArray* ExtraPADATAInfo);
NSData* dataFromHexString(NSString* hex);
NSData* encryptKrbData(krb5_keyusage usage, int enctype, NSData* plaintextDataToEncrypt, NSString* hash);
NSData* createGeneralizedTime(int daysFromNow);
NSData* createASREQ(int enc_type, NSString* hash, NSString* clientName, NSString* domain, bool supportAll, int tgtEnctype, NSArray* PADATATypes, NSArray* ExtraPADATAInfo);
Krb5Ticket parseASREP(NSData* asrep, NSString* hash, int enc_type);
Krb5Ticket parseLKDCASREP(NSData* asrep, NSString* hash, int enc_type);
void parseKerberosTicket(Krb5Ticket* parsedTicket, ASN1_Obj* baseBlob);
NSData* decryptKrbData(krb5_keyusage usage, int enctype, NSData* encryptedData, NSString* hash);
void parseASREPEncData(Krb5Ticket* parsedTicket, ASN1_Obj* baseBlob);
NSData* createTGSREQ(Krb5Ticket TGT, NSString* service, bool kerberoasting, NSString* serviceDomain);
Krb5Ticket parseTGSREP(NSData* tgsrep, Krb5Ticket TGT, bool kerberoasting);
NSData* createS4U2SelfReq(Krb5Ticket TGT, NSString* targetUser);
NSData* createS4U2ProxyReq(Krb5Ticket sTicket, NSString* spn, NSString* spnDomain, NSData* innerTicket);
//LKDC Functions
NSData* LKDC_Stage1_GetRemoteRealm(NSString* username);
NSString* LKDC_Stage1_ParseASREPForRemoteRealm(NSData* LKDC_Stage1_Rep);
NSData* LKDC_Stage2_GetPADATAInfo(NSString* remoteRealm, NSString* username);
