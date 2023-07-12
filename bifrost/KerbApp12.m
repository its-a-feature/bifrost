//
//  KerbApp12.m
//  bifrost
//
//  Created by @its_a_feature_ on 10/14/19.
//  Copyright © 2019 Cody Thomas (@its_a_feature_). All rights reserved.
//

#import <Foundation/Foundation.h>
#import "KerbApp12.h"

@implementation KerbApp12 //TGS-REQ
bool isS4U2Self;
bool isS4U2Proxy;
bool kerberoasting = false;
KerbSequence* PADATA_FOR_USER;
KerbSequence* PADATA_FOR_TGS;
KerbSequence* PADATA_OPTIONS;
KerbGenericString* service;
KerbGenericString* serviceDomain;
KerbGenericString* targetUser; //this is for S4U2Self only
KerbOctetString* key12;
KerbGenericString* requestingUser;
NSData* innerTicket;
KerbSequence* checksumdata;
//standard TGS-REQ information, service should be like cifs/hostname.domain.com
-(NSData*) createAuthenticatorRealm:(KerbGenericString*)realm Principal:(KerbCNamePrincipal*) cname Ticket:(Krb5Ticket)ticket{
    /*
     * Application 2
            Sequence
                [0]
                    Integer - authenticator-vno (5)
                [1]
                    GeneralString - realm
                [2]
                    principal name (cname) CNamePrincipal
                [3]
                    cksum (optional)
                [4]
                    Integer (microseconds)
                [5]
                    GeneralizedTime (now)
     
     Checksum        ::= SEQUENCE {
             cksumtype       [0] Int32,
             checksum        [1] OCTET STRING
     }
                
     */
    @try{
        KerbSequence* sequence = [[KerbSequence alloc] initWithEmpty];
        [sequence addAsn:[[[KerbInteger alloc] initWithValue:5] collapseToAsnObject] inSpot:0];
        [sequence addAsn:[realm collapseToAsnObject] inSpot:1];
        [sequence addAsn:[cname collapseToAsnObject] inSpot:2];
        //now to calculate the checksum
        // build out [4]
        KerbSequence* seq4 = [[KerbSequence alloc] initWithEmpty];
        if(self.isS4U2Proxy){
            [seq4 addAsn:[[[KerbBitString alloc] initWithValue:KDC_OPT_FORWARDABLE | KDC_OPT_RENEWABLE | KDC_OPT_REQUEST_ANONYMOUS | KDC_OPT_RENEWABLE_OK] collapseToAsnObject] inSpot:0];
        }else{
            [seq4 addAsn:[[[KerbBitString alloc] initWithValue:KDC_OPT_FORWARDABLE | KDC_OPT_RENEWABLE | KDC_OPT_CANONICALIZE] collapseToAsnObject] inSpot:0];
        }
        
        if(self.isS4U2Self){
            /*
             [1] (only for S4U2self)                                  0xA1 [length bytes]        ------- OPTIONAL start only for S4U2Self
             SEQUENCE                                                 0x30 [length bytes]
                 [0]                                                  0xA0 [length bytes]
                     INTEGER 1                                        0x02 [length bytes] [value]
                 [1]                                                  0xA1 [length bytes]
                     SEQUENCE                                         0x30 [length bytes]
                         GeneralString username of request user       0x1B [length bytes] [value] ------- OPTIONAL end  only for S4U2Self
             */
            KerbCNamePrincipal* partOneS4U = [[KerbCNamePrincipal alloc] initWithValueUsername:requestingUser.KerbGenStringvalue];
            [seq4 addAsn:[partOneS4U collapseToAsnObject] inSpot:1];
        }else if(self.isS4U2Proxy){
            KerbCNamePrincipal* partOneS4U = [[KerbCNamePrincipal alloc] initWithValueUsername:NULL];
            [seq4 addAsn:[partOneS4U collapseToAsnObject] inSpot:1];
        }else{
            [seq4 addEmptyinSpot:1]; //cname is left empty in TGS-REQ, used only for AS-REQ and S4U2Self
        }
        [seq4 addAsn:[self.serviceDomain collapseToAsnObject] inSpot:2];
        //      parse out the service pieces for [3] of [4]
        if(self.isS4U2Self){
            //in an S4U2Self request, this is the targetUser we're trying to impersonate
            [seq4 addAsn:[[[KerbCNamePrincipal alloc] initWithValueUsername:requestingUser.KerbGenStringvalue] collapseToAsnObject] inSpot:3];
        }else{
            //in a normal service ticket request, this piece is the SName of the principal we're requesting
            NSArray* servicePieces = [self.service.KerbGenStringvalue componentsSeparatedByString:@"/"];
            if( [servicePieces count] != 2){
                printf("Service, %s, is not in the right format\n", self.service.KerbGenStringvalue.UTF8String);
                return NULL;
            }
            [seq4 addAsn:[[[KerbSNamePrincipal alloc] initWithValueAccount:(NSString*)[servicePieces objectAtIndex:0] Domain:(NSString*)[servicePieces objectAtIndex:1]] collapseToAsnObject] inSpot:3];
        }
        
        [seq4 addEmptyinSpot:4];
        [seq4 addAsn:[[[KerbGeneralizedTime alloc] initWithTimeOffset:100] collapseToAsnObject] inSpot:5]; // till time of 100 days from now
        [seq4 addEmptyinSpot:6];
        int nonce = arc4random_uniform(RAND_MAX);
        [seq4 addAsn:[[[KerbInteger alloc] initWithValue:nonce] collapseToAsnObject] inSpot:7];
        NSData* enctype;
        if(self.kerberoasting){
            enctype = [[[KerbInteger alloc] initWithValue:ENCTYPE_ARCFOUR_HMAC] collapseToNSData];
        }else{
            //we're not kerberoasting, so actually try to get back an aes256 service ticket
            NSData* aes256Enc = [[[KerbInteger alloc] initWithValue:ENCTYPE_AES256_CTS_HMAC_SHA1_96] collapseToNSData];
            NSData* aes128Enc = [[[KerbInteger alloc] initWithValue:ENCTYPE_AES128_CTS_HMAC_SHA1_96] collapseToNSData];
            NSData* arcfour = [[[KerbInteger alloc] initWithValue:ENCTYPE_ARCFOUR_HMAC] collapseToNSData];
            NSMutableData* typelist = [[NSMutableData alloc] init];
            [typelist appendData:aes256Enc];
            [typelist appendData:aes128Enc];
            [typelist appendData:arcfour];
            enctype = [[NSData alloc] initWithData:typelist];
        }
        ASN1_Obj* seq8Sequence = createCollapsedAsnBasicType(0x30, enctype);
        [seq4 addAsn:seq8Sequence inSpot:8];
        if(self.isS4U2Proxy){
            [seq4 addEmptyinSpot:9];
            [seq4 addEmptyinSpot:10];
            ASN1_Obj* additionalTickets = createCollapsedAsnBasicType(0x30, self.innerTicket);
            [seq4 addAsn:additionalTickets inSpot:11];
        }
        self.checksumdata = seq4;
        ASN1_Obj* checksum_asn = [self calculateChecksumTicket:ticket];
        if(checksum_asn == NULL){
            [sequence addEmptyinSpot:3];
        }else{
            [sequence addAsn:checksum_asn inSpot:3];
        }
        //[sequence addEmptyinSpot:3];
        nonce = arc4random_uniform(RAND_MAX);
        [sequence addAsn:[[[KerbInteger alloc] initWithValue:nonce] collapseToAsnObject] inSpot:4];
        [sequence addAsn:[[[KerbGeneralizedTime alloc] initWithTimeNow] collapseToAsnObject] inSpot:5];
        NSData* collapsedSequence = [sequence collapseToNSData];
        ASN1_Obj* app2 = createCollapsedAsnBasicType(0x62, collapsedSequence);
        return app2.data;
    }@catch(NSException* exception){
        printf("Error in createAuthenticator: %s\n", exception.reason.UTF8String);
        @throw exception;
    }
}
-(ASN1_Obj*) calculateChecksumTicket: (Krb5Ticket)ticket{
     /*
        krb5_error_code KRB5_CALLCONV
        krb5_c_make_checksum
        (krb5_context context, krb5_cksumtype cksumtype,
                const krb5_keyblock *key, krb5_keyusage usage,
                const krb5_data *input, krb5_checksum *cksum)
        */
    return nil;
    /*
    uint8_t HMACdata[CC_SHA256_DIGEST_LENGTH] = {0};
    NSData* inData = [self.checksumdata collapseToNSData];
    printf("inData: %s\n", [[inData base64EncodedStringWithOptions:0] UTF8String]);
    NSLog(@"inData: %@", inData);
    printf("key data: %s\nkey data length: %d\n", [[ticket.app29.key.KerbOctetvalue base64EncodedStringWithOptions:0] UTF8String], ticket.app29.key.KerbOctetvalue.length);
    NSLog(@"key data: %@", ticket.app29.key.KerbOctetvalue);
    CCHmac(kCCHmacAlgSHA256, ticket.app29.key.KerbOctetvalue.bytes, ticket.app29.key.KerbOctetvalue.length, inData.bytes, inData.length, HMACdata);
    printf("cHMAC: %s\n", [[[[NSData alloc] initWithBytes:HMACdata length:sizeof(HMACdata)] base64EncodedStringWithOptions:0] UTF8String] );
    NSLog(@"cHMAC: %@", [[NSData alloc] initWithBytes:HMACdata length:sizeof(HMACdata)]);
    krb5_checksum checksum = {0}; //malloc(sizeof(krb5_checksum));
    krb5_keyusage usage= {0};
    krb5_data input= {0};
    krb5_keyblock key= {0};
    krb5_context context= {0};
    krb5_cksumtype checksumtype= {0};
    
    krb5_error_code ret;
    if ((ret = krb5_init_context (&context) != 0)){
        printf("[-] Failed to get Kerberos context for checksum generation\n");
        return NULL;
    }
    if(ticket.app29.enctype29.KerbIntValue == ENCTYPE_AES256_CTS_HMAC_SHA1_96){
        checksumtype = CKSUMTYPE_HMAC_SHA1_96_AES256;
        printf("checksum type aes256\n");
    }else if(ticket.app29.enctype29.KerbIntValue == ENCTYPE_AES128_CTS_HMAC_SHA1_96){
        checksumtype = CKSUMTYPE_HMAC_SHA1_96_AES128;
        printf("checksum type aes128\n");
    }else{
        printf("Failed to get checksum type: %d\n", ticket.app29.enctype29.KerbIntValue);
        return NULL;
    }
    checksum.contents = malloc(CC_SHA1_DIGEST_LENGTH);
    printf("checksum size: %d\n", CC_SHA1_DIGEST_LENGTH);
    checksum.checksum_type = checksumtype;
    
    key.length = ticket.app29.key.KerbOctetvalue.length;
    key.magic = KV5M_KEYBLOCK;
    key.enctype = ticket.app29.enctype29.KerbIntValue;
    key.contents = malloc(key.length);
    usage = KRB5_KEYUSAGE_TGS_REQ_AUTH_CKSUM;
    memcpy(key.contents, ticket.app29.key.KerbOctetvalue.bytes, ticket.app29.key.KerbOctetvalue.length);
    input.length = inData.length;
    input.data = malloc(inData.length);
    input.magic = KV5M_CHECKSUM;
    memcpy(input.data, inData.bytes, inData.length);
    krb5_error_code result = krb5_c_make_checksum(context, checksumtype, &key, usage, &input, &checksum);
    printf("result of krb5_c_make_checksum: %d\n", result);
    uint8_t validChecksum = 0;
    result = krb5_c_verify_checksum(context, &key, usage, &input, &checksum, &validChecksum);
    printf("result of krb5_c_verify_checksum: %d with validity checks: %d\n", result, validChecksum);
    NSData* checksumData = [[NSData alloc] initWithBytes:checksum.contents length:checksum.length];
    printf("raw old checksum: %s\n", [[checksumData base64EncodedStringWithOptions:0] UTF8String]);
    KerbOctetString* oldchecksumOctet = [[KerbOctetString alloc] initWithValue:[[NSData alloc] initWithBytes:checksum.contents length:checksum.length]];
    KerbOctetString* checksumOctet = [[KerbOctetString alloc] initWithValue:[[NSData alloc] initWithBytes:HMACdata length:CC_SHA256_DIGEST_LENGTH]];
    printf("oldchecksum: %s\n", [[oldchecksumOctet getHexValue] UTF8String]);
    printf("newchecksum: %s\n", [[checksumOctet getHexValue] UTF8String]);
    KerbSequence* sequence = [[KerbSequence alloc] initWithEmpty];
    [sequence addAsn:[[[KerbInteger alloc] initWithValue:CKSUMTYPE_HMAC_SHA1_96_AES256] collapseToAsnObject] inSpot:0];
    [sequence addAsn:[checksumOctet collapseToAsnObject] inSpot:1];
    return [sequence collapseToAsnObject];
     */
}
-(NSData*) createPADataTGSReq:(Krb5Ticket) ticket{
    /*
     Application 14 (1 elem) ap-req (msg type)
         SEQUENCE (5 elem)
           [0] (1 elem)
             INTEGER 5 pvno (static)
           [1] (1 elem)
             INTEGER 14 krb-ap-req
           [2] (1 elem)
             BIT STRING (32 bit) 0 ap-options
           [3] (1 elem) ticket
             Application 1 (1 elem)
               SEQUENCE (4 elem)
                 [0] (1 elem)
                   INTEGER 5 tkt-vno
                 [1] (1 elem)
                   GeneralString realm
                 [2] (1 elem) sname
                   SEQUENCE (2 elem)
                     [0] (1 elem)
                       INTEGER 1 krb5-nt-principal
                     [1] (1 elem)
                       SEQUENCE (2 elem)
                         GeneralString krbtgt
                         GeneralString domain.com
                 [3] (1 elem) enc-part
                   SEQUENCE (3 elem)
                     [0] (1 elem)
                       INTEGER 18 enc-type
                     [1] (1 elem)
                       INTEGER 12 kvno
                     [2] (1 elem)
                       OCTET STRING (1070 byte)
           [4] (1 elem) authenticator
             SEQUENCE (2 elem)
               [0] (1 elem)
                 INTEGER 18 enctype
               [2] (1 elem)
                 OCTET STRING (179 byte)
     */
    @try{
        KerbSequence* sequence = [[KerbSequence alloc] initWithEmpty];
        [sequence addAsn:[[[KerbInteger alloc] initWithValue:5] collapseToAsnObject] inSpot:0];
        [sequence addAsn:[[[KerbInteger alloc] initWithValue:14] collapseToAsnObject] inSpot:1];
        [sequence addAsn:[[[KerbBitString alloc] initWithValue:0] collapseToAsnObject] inSpot:2];
        [sequence addAsn:[ticket.app1 collapseToAsnObject] inSpot:3];
        //get authenticator data, encrypt it, and set up piece 4 before adding
        NSData* authenticator = [self createAuthenticatorRealm:ticket.app1.realm Principal:ticket.app29.cname Ticket:ticket];
        //NSData* authenticator = createAuthenticator(ticket.app1.realm, ticket.app29.cname);
        NSData* encryptedData = encryptKrbData(KRB5_KEYUSAGE_TGS_REQ_AUTH, ticket.app29.enctype29.KerbIntValue, authenticator, [ticket.app29.key getHexValue]);
        KerbSequence* seqFour = [[KerbSequence alloc] initWithEmpty];
        [seqFour addAsn:[[[KerbInteger alloc] initWithValue:ticket.app29.enctype29.KerbIntValue] collapseToAsnObject] inSpot:0];
        ASN1_Obj* encryptedOctet = createCollapsedAsnBasicType(0x04, encryptedData);
        [seqFour addEmptyinSpot:1];
        [seqFour addAsn:encryptedOctet inSpot:2];
        
        [sequence addAsn:[seqFour collapseToAsnObject] inSpot:4];
        
        ASN1_Obj* app14 = createCollapsedAsnBasicType(0x6E, [sequence collapseToNSData]);
        
        return app14.data;
    }@catch(NSException* exception){
        printf("Error in createPADataTGSReq: %s\n", exception.reason.UTF8String);
        @throw exception;
    }
}
-(id)initWithTicket:(Krb5Ticket*)TGT Service:(NSString*)service TargetDomain:(NSString*)targetDomain Kerberoasting:(bool)kerberoast{
    if(self = [super init]){
        self.PADATA_FOR_USER = NULL;
        self.isS4U2Self = false;
        self.isS4U2Proxy = false;
        self.kerberoasting = kerberoast;
        self.targetUser = NULL;
        self.innerTicket = NULL;
        self.service = [[KerbGenericString alloc] initWithValue:service];
        self.serviceDomain = [[KerbGenericString alloc] initWithValue:targetDomain];
        //create PADATA_FOR_TGS
        KerbSequence* innerSeqFor3 = [[KerbSequence alloc] initWithEmpty];
        [innerSeqFor3 addEmptyinSpot:0];
        [innerSeqFor3 addAsn:[[[KerbInteger alloc] initWithValue:1] collapseToAsnObject] inSpot:1];
        NSData* app14 = [self createPADataTGSReq:*TGT];
        ASN1_Obj* octetOfApp14 = createCollapsedAsnBasicType(0x04, app14);
        [innerSeqFor3 addAsn:octetOfApp14 inSpot:2];
        self.PADATA_FOR_TGS = innerSeqFor3;
    }
    return self;
}
-(id)initForProxyWithTicket:(Krb5Ticket*)sTicket Service:(NSString*)service TargetDomain:(NSString*)targetDomain InnerTicket:(NSData*)innerTicket{
    if(self = [super init]){
        self.PADATA_FOR_USER = NULL;
        self.isS4U2Self = false;
        self.isS4U2Proxy = true;
        self.kerberoasting = false;
        self.targetUser = NULL;
        self.service = [[KerbGenericString alloc] initWithValue:service];
        self.serviceDomain = [[KerbGenericString alloc] initWithValue:targetDomain];
        self.innerTicket = innerTicket;
        //create PADATA_FOR_TGS
        KerbSequence* innerSeqFor3 = [[KerbSequence alloc] initWithEmpty];
        [innerSeqFor3 addEmptyinSpot:0];
        [innerSeqFor3 addAsn:[[[KerbInteger alloc] initWithValue:1] collapseToAsnObject] inSpot:1];
        NSData* app14 = [self createPADataTGSReq:*sTicket];
        ASN1_Obj* octetOfApp14 = createCollapsedAsnBasicType(0x04, app14);
        [innerSeqFor3 addAsn:octetOfApp14 inSpot:2];
        self.PADATA_FOR_TGS = innerSeqFor3;
        //create PADATA-PAC-OPTIONS
        KerbSequence* proxy = [[KerbSequence alloc] initWithEmpty];
        [proxy addEmptyinSpot:0];
        [proxy addAsn:[[[KerbInteger alloc] initWithValue:167] collapseToAsnObject] inSpot:1];
        KerbSequence* bitstringSequence = [[KerbSequence alloc] initWithEmpty];
        [bitstringSequence addAsn:[[[KerbBitString alloc] initWithValue:(16<<24)] collapseToAsnObject] inSpot:0];
        ASN1_Obj* octetOfOptions = createCollapsedAsnBasicType(0x04, [bitstringSequence collapseToNSData]);
        [proxy addAsn:octetOfOptions inSpot:2];
        self.PADATA_OPTIONS = proxy;

    }
    return self;
}
//for S4U2Self
-(NSData*) computeChecksumInData:(NSData*) inData Key:(NSData*) key{
    
    CCHmacContext    ctx, ctx2;
    unsigned char    mac[CC_MD5_DIGEST_LENGTH];
    unsigned char    ksign[CC_MD5_DIGEST_LENGTH];
    NSMutableData* sig = [[NSMutableData alloc] initWithBytes:"signaturekey" length:strlen("signaturekey")];
    unsigned char null = 0x00;
    unsigned char byteUsage[] = { 0x11, 0x00, 0x00, 0x00};
    [sig appendBytes:&null length:1];
    CCHmacInit( &ctx, kCCHmacAlgMD5, key.bytes, key.length);
    CCHmacUpdate( &ctx, sig.mutableBytes, sig.length );
    CCHmacFinal( &ctx, ksign );
    //ksign = HMACMD5(key, signature)
    NSMutableData* span = [[NSMutableData alloc] initWithBytes:byteUsage length:4];
    [span appendData:inData];
    unsigned char   temp[CC_MD5_DIGEST_LENGTH];
    //temp = MD5( usage + inDdata) i.e. MD5(span)
    CC_MD5(span.mutableBytes, span.length, temp);
    CCHmacInit( &ctx2, kCCHmacAlgMD5, ksign, CC_MD5_DIGEST_LENGTH);
    CCHmacUpdate( &ctx2, temp, CC_MD5_DIGEST_LENGTH );
    CCHmacFinal( &ctx2, mac );
    return [[NSData alloc] initWithBytes:mac length:CC_MD5_DIGEST_LENGTH];
}
-(KerbSequence*) createPAForUserKey:(NSData*)key TargetUser:(NSString*) targetUser Realm:(NSString*) realm{
    /* This is just for S4U2Self
     SEQUENCE (2 elem) (another padata, just put sequentially without 0xA0 or anythign)
         [1] (1 elem)
           INTEGER 129 (static krb5-padata-for-user) (this is the s4u2self section that makes it different from a normal tgs-req)
         [2] (1 elem)
           OCTET STRING (1 elem)
             SEQUENCE (4 elem)
               [0] (1 elem)
                 SEQUENCE (2 elem)
                   [0] (1 elem)
                     INTEGER 10 (static krb5-nt-enterprise-principal)
                   [1] (1 elem)
                     SEQUENCE (1 elem)
                       GeneralString (targetuser@domain)
               [1] (1 elem)
                 GeneralString (realm)
               [2] (1 elem)
                 SEQUENCE (2 elem)
                   [0] (1 elem)
                     INTEGER -138 (static cksumtype-hmac-md5)
                   [1] (1 elem)
                     OCTET STRING (16 byte)  (checksum value)
               [3] (1 elem)
                 GeneralString ("Kerberos" - this is the auth type)
     **/
    KerbSequence* sequence = [[KerbSequence alloc] initWithEmpty];
    [sequence addEmptyinSpot:0];
    [sequence addAsn:[[[KerbInteger alloc] initWithValue:129] collapseToAsnObject] inSpot:1];
    //make the inner sequence in element 2
    KerbSequence* ele2Seq = [[KerbSequence alloc] initWithEmpty];
    //make the inner inner sequence
    /*
     SEQUENCE (2 elem)
         [0] (1 elem)
           INTEGER 10 (static krb5-nt-enterprise-principal)
         [1] (1 elem)
           SEQUENCE (1 elem)
             GeneralString (targetuser@domain)
     **/
    KerbCNamePrincipal* cname = [[KerbCNamePrincipal alloc] initWithValueUsername:targetUser];
    cname.krb5_int_principal.KerbIntValue = 10;
    [ele2Seq addAsn:[cname collapseToAsnObject] inSpot:0];
    [ele2Seq addAsn:[[[KerbGenericString alloc] initWithValue:realm] collapseToAsnObject] inSpot:1];
    //generate sequence that includes checksum
    //checksum is over nameType, targetUser, realm, and "Kerberos" (auth package)
    //https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-SFU/%5BMS-SFU%5D.pdf
    Byte nameType[] = {0xA, 0x0, 0x0, 0x0}; // this is a static thing
    NSMutableData* checksumData = [[NSMutableData alloc] initWithBytes:nameType length:4];
    [checksumData appendData:[[NSData alloc] initWithBytes:targetUser.UTF8String length:targetUser.length]];
    [checksumData appendData:[[NSData alloc] initWithBytes:realm.UTF8String length:realm.length]];
    NSString* authPackage = @"Kerberos";
    [checksumData appendData:[[NSData alloc] initWithBytes:authPackage.UTF8String length:authPackage.length]];
    //krb5_c_make_checksum(krb5_context context, krb5_cksumtype cksumtype,const krb5_keyblock *key, krb5_keyusage usage,const krb5_data *input, krb5_checksum *cksum)
    //NSData* checksumResult = computeChecksum(checksumData, key);
    NSData* checksumResult = [self computeChecksumInData:checksumData Key:key];
    KerbSequence* checksumSequence = [[KerbSequence alloc] initWithEmpty];
    [checksumSequence addAsn:[[[KerbInteger alloc] initWithValue:CKSUMTYPE_HMAC_MD5_ARCFOUR] collapseToAsnObject] inSpot:0];
    [checksumSequence addAsn:[[[KerbOctetString alloc] initWithValue:checksumResult] collapseToAsnObject] inSpot:1];
    [ele2Seq addAsn:[checksumSequence collapseToAsnObject] inSpot:2];
    
    [ele2Seq addAsn:[[[KerbGenericString alloc] initWithValue:@"Kerberos"] collapseToAsnObject] inSpot:3];
    //collapse ele2Seq to NSData and use for octet string
    KerbOctetString* ele2SeqOctetString = [[KerbOctetString alloc] initWithValue:[ele2Seq collapseToNSData]];
    [sequence addAsn:[ele2SeqOctetString collapseToAsnObject] inSpot:2];
    return sequence;
}
-(id)initWithTicket:(Krb5Ticket*)TGT TargetUser:(NSString*)targetUser TargetDomain:(NSString*)targetDomain{
    if(self = [super init]){
        self.isS4U2Self = true;
        self.isS4U2Proxy = false;
        self.kerberoasting = false;
        self.innerTicket = NULL;
        self.targetUser = [[KerbGenericString alloc] initWithValue:targetUser];
        self.serviceDomain = [[KerbGenericString alloc] initWithValue:targetDomain];
        self.service = NULL;
        requestingUser = TGT->app29.cname.username;
        //create PADATA_FOR_TGS
        KerbSequence* innerSeqFor3 = [[KerbSequence alloc] initWithEmpty];
        [innerSeqFor3 addEmptyinSpot:0];
        [innerSeqFor3 addAsn:[[[KerbInteger alloc] initWithValue:1] collapseToAsnObject] inSpot:1];
        NSData* app14 = [self createPADataTGSReq:*TGT];
        ASN1_Obj* octetOfApp14 = createCollapsedAsnBasicType(0x04, app14);
        [innerSeqFor3 addAsn:octetOfApp14 inSpot:2];
        self.PADATA_FOR_TGS = innerSeqFor3;
        //CREATE padata_for_user
        self.key12 = TGT->app29.key;
        self.PADATA_FOR_USER = [self createPAForUserKey:TGT->app29.key.KerbOctetvalue TargetUser:targetUser Realm:targetDomain];
    }
    return self;
}
-(NSData*)collapseToNSData{
    return [self collapseToAsnObject].data;
}
-(ASN1_Obj*)collapseToAsnObject{
    KerbSequence* outerSequence = [[KerbSequence alloc] initWithEmpty];
    [outerSequence addEmptyinSpot:0];
    [outerSequence addAsn:[[[KerbInteger alloc] initWithValue:5] collapseToAsnObject] inSpot:1];
    [outerSequence addAsn:[[[KerbInteger alloc] initWithValue:12] collapseToAsnObject] inSpot:2];
    //build out [3]
    // this is buildin gout the sequence of PA_DATA objects
    ASN1_Obj* outter3Seq;
    if(self.isS4U2Self){
        ASN1_Obj* padata_for_tgs = [self.PADATA_FOR_TGS collapseToAsnObject];
        ASN1_Obj* padata_for_user = [[self createPAForUserKey:self.key12.KerbOctetvalue TargetUser:self.targetUser.KerbGenStringvalue Realm:self.serviceDomain.KerbGenStringvalue] collapseToAsnObject];
        NSData* appended = appendAsnObj(padata_for_tgs, padata_for_user);
        outter3Seq = createCollapsedAsnBasicType(0x30, appended);
        
    }else if(self.isS4U2Proxy){
        ASN1_Obj* padata_for_tgs = [self.PADATA_FOR_TGS collapseToAsnObject];
        ASN1_Obj* padata_options = [self.PADATA_OPTIONS collapseToAsnObject];
        NSData* appended = appendAsnObj(padata_for_tgs, padata_options);
        outter3Seq = createCollapsedAsnBasicType(0x30, appended);
    }
    else{
        //this is self.PADATA_FOR_TGS
        outter3Seq = createCollapsedAsnBasicType(0x30, [self.PADATA_FOR_TGS collapseToNSData]);
    }
    [outerSequence addAsn:outter3Seq inSpot:3];
    // build out [4]
    KerbSequence* seq4 = [[KerbSequence alloc] initWithEmpty];
    if(self.isS4U2Proxy){
        [seq4 addAsn:[[[KerbBitString alloc] initWithValue:KDC_OPT_FORWARDABLE | KDC_OPT_RENEWABLE | KDC_OPT_REQUEST_ANONYMOUS | KDC_OPT_RENEWABLE_OK] collapseToAsnObject] inSpot:0];
    }else{
        [seq4 addAsn:[[[KerbBitString alloc] initWithValue:KDC_OPT_FORWARDABLE | KDC_OPT_RENEWABLE | KDC_OPT_CANONICALIZE] collapseToAsnObject] inSpot:0];
    }
    
    if(self.isS4U2Self){
        /*
         [1] (only for S4U2self)                                  0xA1 [length bytes]        ------- OPTIONAL start only for S4U2Self
         SEQUENCE                                                 0x30 [length bytes]
             [0]                                                  0xA0 [length bytes]
                 INTEGER 1                                        0x02 [length bytes] [value]
             [1]                                                  0xA1 [length bytes]
                 SEQUENCE                                         0x30 [length bytes]
                     GeneralString username of request user       0x1B [length bytes] [value] ------- OPTIONAL end  only for S4U2Self
         */
        KerbCNamePrincipal* partOneS4U = [[KerbCNamePrincipal alloc] initWithValueUsername:requestingUser.KerbGenStringvalue];
        [seq4 addAsn:[partOneS4U collapseToAsnObject] inSpot:1];
    }else if(self.isS4U2Proxy){
        KerbCNamePrincipal* partOneS4U = [[KerbCNamePrincipal alloc] initWithValueUsername:NULL];
        [seq4 addAsn:[partOneS4U collapseToAsnObject] inSpot:1];
    }else{
        [seq4 addEmptyinSpot:1]; //cname is left empty in TGS-REQ, used only for AS-REQ and S4U2Self
    }
    [seq4 addAsn:[self.serviceDomain collapseToAsnObject] inSpot:2];
    //      parse out the service pieces for [3] of [4]
    if(self.isS4U2Self){
        //in an S4U2Self request, this is the targetUser we're trying to impersonate
        [seq4 addAsn:[[[KerbCNamePrincipal alloc] initWithValueUsername:requestingUser.KerbGenStringvalue] collapseToAsnObject] inSpot:3];
    }else{
        //in a normal service ticket request, this piece is the SName of the principal we're requesting
        NSArray* servicePieces = [self.service.KerbGenStringvalue componentsSeparatedByString:@"/"];
        if( [servicePieces count] != 2){
            printf("Service, %s, is not in the right format\n", self.service.KerbGenStringvalue.UTF8String);
            return NULL;
        }
        [seq4 addAsn:[[[KerbSNamePrincipal alloc] initWithValueAccount:(NSString*)[servicePieces objectAtIndex:0] Domain:(NSString*)[servicePieces objectAtIndex:1]] collapseToAsnObject] inSpot:3];
    }
    
    [seq4 addEmptyinSpot:4];
    [seq4 addAsn:[[[KerbGeneralizedTime alloc] initWithTimeOffset:100] collapseToAsnObject] inSpot:5]; // till time of 100 days from now
    [seq4 addEmptyinSpot:6];
    int nonce = arc4random_uniform(RAND_MAX);
    [seq4 addAsn:[[[KerbInteger alloc] initWithValue:nonce] collapseToAsnObject] inSpot:7];
    NSData* enctype;
    if(self.kerberoasting){
        enctype = [[[KerbInteger alloc] initWithValue:ENCTYPE_ARCFOUR_HMAC] collapseToNSData];
    }else{
        //we're not kerberoasting, so actually try to get back an aes256 service ticket
        NSData* aes256Enc = [[[KerbInteger alloc] initWithValue:ENCTYPE_AES256_CTS_HMAC_SHA1_96] collapseToNSData];
        NSData* aes128Enc = [[[KerbInteger alloc] initWithValue:ENCTYPE_AES128_CTS_HMAC_SHA1_96] collapseToNSData];
        NSData* arcfour = [[[KerbInteger alloc] initWithValue:ENCTYPE_ARCFOUR_HMAC] collapseToNSData];
        NSMutableData* typelist = [[NSMutableData alloc] init];
        [typelist appendData:aes256Enc];
        [typelist appendData:aes128Enc];
        [typelist appendData:arcfour];
        enctype = [[NSData alloc] initWithData:typelist];
    }
    ASN1_Obj* seq8Sequence = createCollapsedAsnBasicType(0x30, enctype);
    [seq4 addAsn:seq8Sequence inSpot:8];
    if(self.isS4U2Proxy){
        [seq4 addEmptyinSpot:9];
        [seq4 addEmptyinSpot:10];
        ASN1_Obj* additionalTickets = createCollapsedAsnBasicType(0x30, self.innerTicket);
        [seq4 addAsn:additionalTickets inSpot:11];
    }
    [outerSequence addAsn:[seq4 collapseToAsnObject] inSpot:4];
    ASN1_Obj* app12 = createCollapsedAsnBasicType(0x6C, [outerSequence collapseToNSData]);
    return app12;
}
@end
