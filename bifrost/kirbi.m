//
//  kirbi.m
//  bifrost
//
//  Created by @its_a_feature_ on 10/14/19.
//  Copyright © 2019 Cody Thomas (@its_a_feature_). All rights reserved.
//

#import "kirbi.h"
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonHMAC.h>

NSString* describeFlags(int flag){
    /*
     #define    TKT_FLG_FORWARDABLE        0x40000000
     #define    TKT_FLG_FORWARDED        0x20000000
     #define    TKT_FLG_PROXIABLE        0x10000000
     #define    TKT_FLG_PROXY            0x08000000
     #define    TKT_FLG_MAY_POSTDATE        0x04000000
     #define    TKT_FLG_POSTDATED        0x02000000
     #define    TKT_FLG_INVALID            0x01000000
     #define    TKT_FLG_RENEWABLE        0x00800000
     #define    TKT_FLG_INITIAL            0x00400000
     #define    TKT_FLG_PRE_AUTH        0x00200000
     #define    TKT_FLG_HW_AUTH            0x00100000
     #define    TKT_FLG_TRANSIT_POLICY_CHECKED    0x00080000
     #define    TKT_FLG_OK_AS_DELEGATE        0x00040000
     #define    TKT_FLG_ANONYMOUS        0x00020000
     **/
    NSMutableString* flags = [[NSMutableString alloc] init];
    if((flag & TKT_FLG_FORWARDABLE) > 0){
        [flags appendFormat:@"forwardable "];
    }
    if((flag & TKT_FLG_FORWARDED) > 0){
        [flags appendFormat:@"forwarded "];
    }
    if((flag & TKT_FLG_PROXIABLE) > 0){
        [flags appendFormat:@"proxiable "];
    }
    if((flag & TKT_FLG_PROXY) > 0){
        [flags appendFormat:@"proxy "];
    }
    if((flag & TKT_FLG_MAY_POSTDATE) > 0){
        [flags appendFormat:@"may-postdate "];
    }
    if((flag & TKT_FLG_POSTDATED) > 0){
        [flags appendFormat:@"postdated "];
    }
    if((flag & TKT_FLG_INVALID) > 0){
        [flags appendFormat:@"invalid "];
    }
    if((flag & TKT_FLG_RENEWABLE) > 0){
        [flags appendFormat:@"renewable "];
    }
    if((flag & TKT_FLG_INITIAL) > 0){
        [flags appendFormat:@"initial "];
    }
    if((flag & TKT_FLG_PRE_AUTH) > 0){
        [flags appendFormat:@"pre-auth "];
    }
    if((flag & TKT_FLG_HW_AUTH) > 0){
        [flags appendFormat:@"hardware-auth "];
    }
    if((flag & TKT_FLG_TRANSIT_POLICY_CHECKED) > 0){
        [flags appendFormat:@"transit-policy-checked "];
    }
    if((flag & TKT_FLG_OK_AS_DELEGATE) > 0){
        [flags appendFormat:@"ok-as-delegate "];
    }
    if((flag & TKT_FLG_ANONYMOUS) > 0){
        [flags appendFormat:@"anonymous "];
    }
    return flags;
}
NSString* describeTicket(Krb5Ticket ticket){
    NSMutableString* desc = [[NSMutableString alloc] init];
    @try{
        [desc appendFormat:@"Client: %s@%s\n", ticket.app29.cname.username.KerbGenStringvalue.UTF8String, ticket.app29.realm29.KerbGenStringvalue.UTF8String];
        [desc appendFormat:@"Principal: %s@%s\n", [ticket.app29.sname29 getNSString].UTF8String, ticket.app29.realm29.KerbGenStringvalue.UTF8String];
        [desc appendFormat:@"Start: %s\nEnd:   %s\nRenew: %s\n", ticket.app29.start.printTimeUTC.UTF8String,
         ticket.app29.end.printTimeUTC.UTF8String, ticket.app29.till.printTimeUTC.UTF8String];
        if(ticket.app29.enctype29.KerbIntValue == ENCTYPE_AES256_CTS_HMAC_SHA1_96){
            [desc appendFormat:@"Key Type: AES256_CTS_HMAC_SHA1_96\nKey Value: %s (", [ticket.app29.key.KerbOctetvalue base64EncodedStringWithOptions:0].UTF8String];
        }else if(ticket.app29.enctype29.KerbIntValue == ENCTYPE_AES128_CTS_HMAC_SHA1_96){
            [desc appendFormat:@"Key Type: AES126_CTS_HMAC_SHA1_96\nKey Value: %s (", [ticket.app29.key.KerbOctetvalue base64EncodedStringWithOptions:0].UTF8String];
        }else if(ticket.app29.enctype29.KerbIntValue == ENCTYPE_ARCFOUR_HMAC){
            [desc appendFormat:@"Key Type: ARCFOUR_HMAC\nKey Value: %s (", [ticket.app29.key.KerbOctetvalue base64EncodedStringWithOptions:0].UTF8String];
        }else{
            [desc appendFormat:@"Key Type: %d\nKey Value: %s (", ticket.app29.enctype29.KerbIntValue, [ticket.app29.key.KerbOctetvalue base64EncodedStringWithOptions:0].UTF8String];
        }
        for(int i = 0; i < ticket.app29.key.KerbOctetvalue.length; i++){
            [desc appendFormat:@"%02X", ((Byte*)ticket.app29.key.KerbOctetvalue.bytes)[i]];
        }
        [desc appendFormat:@")\n"];
        [desc appendFormat:@"Flags: %s", describeFlags(ticket.app29.flags.KerbBitValue).UTF8String];
        return desc;
    }@catch(NSException* exception){
        [desc appendFormat:@"\nParsing error: %s\n", exception.reason.UTF8String];
        return desc;
    }
}
Krb5Ticket parseKirbi(NSData* data){
    //given an NSData of bytes of a kirbi file, parse it into a Krb5Ticket in app1 and app29 data
    Krb5Ticket ticket;
    @try{
        if(data.bytes == nil){
            @throw [[NSException alloc] initWithName:@"Null data" reason:@"Null data" userInfo:NULL];
        }
        ASN1_Obj* baseObject = [[ASN1_Obj alloc] initWithType:0x76 Length:0 Data:data];
        ASN1_Obj* curObj = getNextAsnBlob(baseObject); //should now be looking at 0x76, application 22
        curObj = getNextAsnBlob(baseObject); // sequence 0x30
        curObj = getNextAsnBlob(baseObject); // [0] 0xA0
        curObj = getNextAsnBlob(baseObject); // int - kvno
        curObj = getNextAsnBlob(baseObject); // [1] 0xA1
        curObj = getNextAsnBlob(baseObject); // int - 22
        curObj = getNextAsnBlob(baseObject); // [2] 0xA2
        curObj = getNextAsnBlob(baseObject); // sequence 0x30
        ticket.app1 = [[KerbApp1 alloc] initWithObject:carveAsnBlobObject(baseObject)]; //fill out app1 and move past it
        curObj = getNextAsnBlob(baseObject); // [3] 0xA3
        curObj = getNextAsnBlob(baseObject); // sequence 0x30
        curObj = getNextAsnBlob(baseObject); // [0] 0xA0
        curObj = getNextAsnBlob(baseObject); // int - 0
        curObj = getNextAsnBlob(baseObject); // [2] 0xA2
        curObj = getNextAsnBlob(baseObject); // octet string 0x04
        NSData* app29data = getAsnOctetStringBlob(curObj);
        ASN1_Obj* app29Obj = [[ASN1_Obj alloc] initWithType:0x7D Length:app29data.length Data:app29data];
        ticket.app29 = [[KerbApp29 alloc] initWithObject:app29Obj];
        return ticket;
    }@catch(NSException* exception){
        printf("[-] Error in parseKirbi: %s\n", exception.reason.UTF8String);
        @throw exception;
    }
}
NSData* createKirbi(Krb5Ticket krb_cred){
    /*
     Application 22 (1 elem)
         SEQUENCE (4 elem)
           [0] (1 elem)
             INTEGER 5
           [1] (1 elem)
             INTEGER 22
           [2] (1 elem)
             SEQUENCE (1 elem)
               Application 1 (1 elem)
                 SEQUENCE (4 elem)
                   [0] (1 elem)
                     INTEGER 5
                   [1] (1 elem)
                     GeneralString
                   [2] (1 elem)
                     SEQUENCE (2 elem)
                       [0] (1 elem)
                         INTEGER 2
                       [1] (1 elem)
                         SEQUENCE (2 elem)
                           GeneralString
                           GeneralString
                   [3] (1 elem)
                     SEQUENCE (3 elem)
                       [0] (1 elem)
                         INTEGER 18
                       [1] (1 elem)
                         INTEGER 12
                       [2] (1 elem)
                         OCTET STRING (1062 byte)
           [3] (1 elem)
             SEQUENCE (2 elem)
               [0] (1 elem)
                 INTEGER 0
               [2] (1 elem)
                 OCTET STRING (1 elem)
                   Application 29 (1 elem)
                     SEQUENCE (1 elem)
                       [0] (1 elem)
                         SEQUENCE (1 elem)
                           SEQUENCE (9 elem)
                             [0] (1 elem)
                               SEQUENCE (2 elem)
                                 [0] (1 elem)
                                   INTEGER 18
                                 [1] (1 elem)
                                   OCTET STRING (32 byte)
                             [1] (1 elem)
                               GeneralString
                             [2] (1 elem)
                               SEQUENCE (2 elem)
                                 [0] (1 elem)
                                   INTEGER 1
                                 [1] (1 elem)
                                   SEQUENCE (1 elem)
                                     GeneralString
                             [3] (1 elem)
                               BIT STRING (32 bit) 01100000101000010000000000000000
                             [5] (1 elem)
                               GeneralizedTime 2019-10-18 17:39:42 UTC
                             [6] (1 elem)
                               GeneralizedTime 2019-10-19 03:39:42 UTC
                             [7] (1 elem)
                               GeneralizedTime 2019-10-25 17:38:49 UTC
                             [8] (1 elem)
                               GeneralString
                             [9] (1 elem)
                               SEQUENCE (2 elem)
                                 [0] (1 elem)
                                   INTEGER 2
                                 [1] (1 elem)
                                   SEQUENCE (2 elem)
                                     GeneralString
                                     GeneralString
     */
    @try{
        NSMutableArray<ASN1_Obj*> *sequence = [[NSMutableArray<ASN1_Obj*> alloc] init];
        ASN1_Obj* collapsedZero = [[[KerbInteger alloc] initWithValue: 0] collapseToAsnObject];
        ASN1_Obj* collapsedVno = [[[KerbInteger alloc] initWithValue: krb_cred.app1.kvno.KerbIntValue] collapseToAsnObject];
        ASN1_Obj* collapsed22 = [[[KerbInteger alloc] initWithValue: 22] collapseToAsnObject];
        //create the bottom principal sequence [9] is really just the collapsed sname from app1
        ASN1_Obj* sequenceNine = [krb_cred.app1.sname collapseToAsnObject];
        //generate the sequence with the client principal [2]
        ASN1_Obj* sequenceTwo = [krb_cred.app29.cname collapseToAsnObject];
        //generate the sequence with key and encryption type [0]
        ASN1_Obj* collapsedEncType = [krb_cred.app29.enctype29 collapseToAsnObject];
        ASN1_Obj* collapsedKey = [krb_cred.app29.key collapseToAsnObject];
        [sequence removeAllObjects];
        [sequence insertObject:collapsedEncType atIndex:0];
        [sequence insertObject:collapsedKey atIndex:1];
        ASN1_Obj* sequenceZero = collapseAsnSequence(sequence);
        //generate sequence of 10 elements
        [sequence removeAllObjects];
        [sequence insertObject:sequenceZero atIndex:0];
        ASN1_Obj* collapsedRealm = [krb_cred.app1.realm collapseToAsnObject];
        [sequence insertObject:collapsedRealm atIndex:1];
        [sequence insertObject:sequenceTwo atIndex:2];

        ASN1_Obj* collapsedFlags = [krb_cred.app29.flags collapseToAsnObject];
        [sequence insertObject:collapsedFlags atIndex:3];
        ASN1_Obj* collapsedStartTime = [krb_cred.app29.start collapseToAsnObject];
        ASN1_Obj* collapsedEndTime = [krb_cred.app29.end collapseToAsnObject];
        ASN1_Obj* collapsedRenewTime = [krb_cred.app29.till collapseToAsnObject];
        [sequence insertObject:[ASN1_Obj alloc] atIndex:4];
        [sequence insertObject:collapsedStartTime atIndex:5];
        [sequence insertObject:collapsedEndTime atIndex:6];
        [sequence insertObject:collapsedRenewTime atIndex:7];
        [sequence insertObject:collapsedRealm atIndex:8];
        [sequence insertObject:sequenceNine atIndex:9];
        ASN1_Obj* sequenceOfNine = collapseAsnSequence(sequence);
        // add sequence of 9 to sequence front-end
        ASN1_Obj* collapsedSequenceOfNineSequence = collapseAsnBasicType([[ASN1_Obj alloc] initWithType:0x30 Length:0x00 Data:sequenceOfNine.data]);
        [sequence removeAllObjects];
        [sequence insertObject:collapsedSequenceOfNineSequence atIndex:0];
        ASN1_Obj* application29Sequence = collapseAsnSequence(sequence);
        //add application29 (0x7D) to the front
        ASN1_Obj* application29 = collapseAsnBasicType([[ASN1_Obj alloc] initWithType:0x7D Length:0x00 Data:application29Sequence.data]);
        //add octet string (0x04) to the front
        ASN1_Obj* octetOfApplication29 = collapseAsnBasicType([[ASN1_Obj alloc] initWithType:0x04 Length:0x00 Data:application29.data]);
        //create high level sequence 3
        [sequence removeAllObjects];
        [sequence insertObject:collapsedZero atIndex:0];
        [sequence insertObject:[ASN1_Obj alloc] atIndex:1];
        [sequence insertObject:octetOfApplication29 atIndex:2];
        ASN1_Obj* sequenceThree = collapseAsnSequence(sequence);
        //create highest level sequence
        [sequence removeAllObjects];
        [sequence insertObject:collapsedVno atIndex:0];
        [sequence insertObject:collapsed22 atIndex:1];
 
        ASN1_Obj* application1 = collapseAsnBasicType([[ASN1_Obj alloc] initWithType:0x30 Length:0x00 Data:[krb_cred.app1 collapseToNSData]]);
        [sequence insertObject:application1 atIndex:2];
        [sequence insertObject:sequenceThree atIndex:3];
        ASN1_Obj* highestSequence = collapseAsnSequence(sequence);
        ASN1_Obj* application22 = collapseAsnBasicType([[ASN1_Obj alloc] initWithType:0x76 Length:0x00 Data:highestSequence.data]);
        return application22.data;
    }@catch(NSException* exception){
        printf("Error in createKirbi: %s\n", exception.reason.UTF8String);
        @throw exception;
    }
}
NSData* createASREQ(int enc_type, NSString* hash, NSString* clientName, NSString* domain, bool supportAll, int tgtEnctype){
    /* Application 10 (0x6A)
            Sequence (0x30)
                [1]
                    INTEGER pvno (5)
                [2]
                    INTEGER msg-type (10)
                [3] PA-DATA (0xA3)
                    Sequence (0x30)
                        sequence (0x30)
                            [1]
                                INTEGER pdata-type (val 2 - krb5-padata-enc-timestamp)
                            [2]
                                OCTET STRING (0x04)
                                    Sequence (0x30)
                                        [0]
                                            INTEGER enctype (18)
                                        [2]
                                            OCTETSTRING (0x04) 56 bytes  enc value
                        sequence (0x30)
                            [1] INTEGER (pdata-type 149) (KRB5-PDATA-REQ-ENC-PA-REP)
                            [2] OCTET STRING (0 bytes, so 0x04 00)
                [4] KDC-REQ-BODY
                    SEQUENCE (0x30)
                        [0] KDCOptions (KDC_TKT_COMMON_MASK) (bitstring of 32bits)
                        [1] PrincipalName (cname) optional - client username
                            Sequence
                                [0] INTEGER (val 1) - means KRB5-NT-PRINCIPAL
                                [1]
                                    Sequence
                                        General String (username)
                        [2] REALM
                            GeneralString (realm)
                        [3] PrincipalName (sname) optional - server
                            Sequence
                                [0] Integer (val 2) - MEANS krb5-nt-srv-inst
                                [1] Sequence
                                    GeneralString (krbtgt)
                                    GeneralString (realm)
                        [4] KerberosTime (from) (optional, skipped)
                        [5] KerberosTime (till) (generalizedTime format like before, 0x18)
                            GeneralizedTime
                        [6] KerberosTime (rtime - renew time) (optional, skipped)
                            GeneralizedTime (supplied in kinit request)
                        [7] Uint32 (nonce) (random 4byte value)
                            Integer
                        [8]  - etype list in preference order
                            Sequence
                                Integer 18
                                Integer 17
                                Integer 16
                                Integer 23
                        [9] addresses HostAddresses optional (optional, skipped)
                        [10] EncryptedData (enc-authorization-data) (optional, skipped)
                        [11] Sequence of Ticket (additional-tickets) (optional, skipped) (used for S4U2Proxy)
     *
     */
    @try{
        // [1] INTEGER pvno (5)
        ASN1_Obj* collapsedPvno = [[[KerbInteger alloc] initWithValue:5] collapseToAsnObject];
        // [2] INTEGER msg-type (10)
        ASN1_Obj* collapsedMsgType = [[[KerbInteger alloc] initWithValue:10] collapseToAsnObject];
        // [3] PA-DATA
        NSData* padata = createPADataASReq(enc_type, hash);
        ASN1_Obj* collapsedPAData = [[ASN1_Obj alloc] initWithType:0x30 Length:padata.length Data:padata];
        // [4] KDC-REQ-BODY, sequence of the following
        //     [0]
        ASN1_Obj* collapsedKDCOptions = [[[KerbBitString alloc] initWithValue:KDC_OPT_FORWARDABLE | KDC_OPT_RENEWABLE | KDC_OPT_CANONICALIZE ] collapseToAsnObject];
        //     [1]
        ASN1_Obj* collapsedCName = [[[KerbCNamePrincipal alloc] initWithValueUsername:clientName] collapseToAsnObject];
        //     [2]
        ASN1_Obj* collapsedRealm = [[[KerbGenericString alloc] initWithValue:domain] collapseToAsnObject];
        //     [3]
        ASN1_Obj* collapsedSName = [[[KerbSNamePrincipal alloc] initWithValueAccount:@"krbtgt" Domain:domain] collapseToAsnObject];
        //     [4] is skipped
        //     [5]
        ASN1_Obj* collapsedTill = [[[KerbGeneralizedTime alloc] initWithTimeOffset:1] collapseToAsnObject];
        //     [6]
        ASN1_Obj* collapsedRtime = [[[KerbGeneralizedTime alloc] initWithTimeOffset:10] collapseToAsnObject];
        //     [7]
        int nonce = arc4random_uniform(RAND_MAX);
        ASN1_Obj* collapsedNonce = [[[KerbInteger alloc] initWithValue:nonce] collapseToAsnObject];
        //     [8]
        ASN1_Obj* collapsedSeqOfETypes;
        if(supportAll){
            NSData* aes256Enc = [[[KerbInteger alloc] initWithValue:ENCTYPE_AES256_CTS_HMAC_SHA1_96] collapseToNSData];
            NSData* aes128Enc = [[[KerbInteger alloc] initWithValue:ENCTYPE_AES128_CTS_HMAC_SHA1_96] collapseToNSData];
            NSData* arcfour = [[[KerbInteger alloc] initWithValue:ENCTYPE_ARCFOUR_HMAC] collapseToNSData];
            NSMutableData* typelist = [[NSMutableData alloc] init];
            [typelist appendData:aes256Enc];
            [typelist appendData:aes128Enc];
            [typelist appendData:arcfour];
            collapsedSeqOfETypes = createCollapsedAsnBasicType(0x30, [[NSData alloc] initWithData:typelist]);
        }else{
            //say we only support the enctype associated with our key, so we can force an RC4 ticket for example
            ASN1_Obj* collapsedEncType = createCollapsedAsnBasicType(0x02, minimizeAsnInteger(tgtEnctype));
            collapsedSeqOfETypes = createCollapsedAsnBasicType(0x30, collapsedEncType.data);
        }
        
        NSMutableArray<ASN1_Obj*> *sequence = [[NSMutableArray<ASN1_Obj*> alloc] init];
        
        [sequence insertObject:collapsedKDCOptions atIndex:0];
        [sequence insertObject:collapsedCName atIndex:1];
        [sequence insertObject:collapsedRealm atIndex:2];
        [sequence insertObject:collapsedSName atIndex:3];
        [sequence insertObject:[ASN1_Obj alloc] atIndex:4]; // skipped, empty
        [sequence insertObject:collapsedTill atIndex:5];
        [sequence insertObject:collapsedRtime atIndex:6];
        [sequence insertObject:collapsedNonce atIndex:7];
        [sequence insertObject:collapsedSeqOfETypes atIndex:8];
        ASN1_Obj* collapsedKDCBody = collapseAsnSequence(sequence);
        
        //now to make the highest level sequence
        [sequence removeAllObjects];
        [sequence insertObject:[ASN1_Obj alloc] atIndex:0]; //skipped, empty
        [sequence insertObject:collapsedPvno atIndex:1];
        [sequence insertObject:collapsedMsgType atIndex:2];
        [sequence insertObject:collapsedPAData atIndex:3];
        [sequence insertObject:collapsedKDCBody atIndex:4];
        ASN1_Obj* collapsedMainSequence = collapseAsnSequence(sequence);
        
        //wrap it all in application 10
        ASN1_Obj* result = createCollapsedAsnBasicType(0x6A, collapsedMainSequence.data);
        return result.data;
    }@catch(NSException* exception){
        printf("Error in createASREQ: %s\n", exception.reason.UTF8String);
        @throw exception;
    }
}
Krb5Ticket parseASREP(NSData* asrep, NSString* hash, int enc_type){
    /*
     *Application 11 (1 elem) (0x6B)
         SEQUENCE (7 elem)
           [0] (1 elem)
             INTEGER 5 pvno
           [1] (1 elem)
             INTEGER 11 krb-as-rep
           [2] (1 elem)
             SEQUENCE (1 elem)
               SEQUENCE (2 elem)
                 [1] (1 elem)
                   INTEGER 19 krb5-padata-etype-info2
                 [2] (1 elem)
                   OCTET STRING (1 elem)
                     SEQUENCE (1 elem)
                       SEQUENCE (2 elem)
                         [0] (1 elem)
                           INTEGER 18 enctype
                         [1] (1 elem)
                           GeneralString salt (DOMAINclientprincipal)
           [3] (1 elem)
             GeneralString realm
           [4] (1 elem) cname
             SEQUENCE (2 elem)
               [0] (1 elem)
                 INTEGER 1 krbt-nt-principal
               [1] (1 elem)
                 SEQUENCE (1 elem)
                   GeneralString username
           [5] (1 elem)
             Application 1 (1 elem)
               SEQUENCE (4 elem)
                 [0] (1 elem)
                   INTEGER 5 tkt-vno
                 [1] (1 elem)
                   GeneralString realm
                 [2] (1 elem) sname
                   SEQUENCE (2 elem)
                     [0] (1 elem)
                       INTEGER 2 krb5-nt-srv-inst
                     [1] (1 elem)
                       SEQUENCE (2 elem)
                         GeneralString (krbtgt)
                         GeneralString (domain)
                 [3] (1 elem)
                   SEQUENCE (3 elem)
                     [0] (1 elem)
                       INTEGER 18 (enctype)
                     [1] (1 elem)
                       INTEGER 12 kvno
                     [2] (1 elem)
                       OCTET STRING (1070 byte) cipher encoded data
           [6] (1 elem) enc-part
             SEQUENCE (3 elem)
               [0] (1 elem)
                 INTEGER 18 enctype
               [1] (1 elem)
                 INTEGER 7 kvno
               [2] (1 elem)
                 OCTET STRING (319 byte) cipher encoded data **enc2
     
     
     **enc 2
     Application 25 (1 elem)
         SEQUENCE (12 elem)
           [0] (1 elem)
             SEQUENCE (2 elem)
               [0] (1 elem)
                 INTEGER 18
               [1] (1 elem)
                 OCTET STRING (32 byte) key
           [1] (1 elem)
             SEQUENCE (1 elem)
               SEQUENCE (2 elem)
                 [0] (1 elem)
                   INTEGER 0
                 [1] (1 elem)
                   GeneralizedTime 2019-10-24 05:22:07 UTC
           [2] (1 elem)
             INTEGER nonce
           [3] (1 elem)
             GeneralizedTime 2037-09-14 02:48:05 UTC
           [4] (1 elem)
             BIT STRING (32 bit) 01000000111000010000000000000000
           [5] (1 elem)
             GeneralizedTime 2019-10-24 05:22:07 UTC (auth)
           [6] (1 elem)
             GeneralizedTime 2019-10-24 05:22:07 UTC (start)
           [7] (1 elem)
             GeneralizedTime 2019-10-25 05:22:07 UTC (end)
           [8] (1 elem)
             GeneralizedTime 2019-10-31 05:22:07 UTC (renew)
           [9] (1 elem)
             GeneralString
           [10] (1 elem)
             SEQUENCE (2 elem)
               [0] (1 elem)
                 INTEGER 2
               [1] (1 elem)
                 SEQUENCE (2 elem)
                   GeneralString
                   GeneralString
           [12] (1 elem)
             SEQUENCE (1 elem)
               SEQUENCE (2 elem)
                 [1] (1 elem)
                   INTEGER 149
                 [2] (1 elem)
                   OCTET STRING (1 elem)
                     SEQUENCE (2 elem)
                       [0] (1 elem)
                         INTEGER 16
                       [1] (1 elem)
                         OCTET STRING (12 byte)
     */
    Krb5Ticket TGT;
    @try{
        ASN1_Obj* baseBlob = [[ASN1_Obj alloc] initWithType: ((Byte*)asrep.bytes)[0] Length:asrep.length Data:[[NSData alloc] initWithBytes:asrep.bytes length:asrep.length]];
        ASN1_Obj* curBlob;
        curBlob = getNextAsnBlob(baseBlob); //parse the main blob to indicate application 11
        if(curBlob.type == 0x6B || curBlob.type == 0x7E){
            //we're looking at an ASREP
            curBlob = getNextAsnBlob(baseBlob); // gets 0x30
            curBlob = getNextAsnBlob(baseBlob); // gets 0xA0
            curBlob = getNextAsnBlob(baseBlob); // gets 0x02 - should always be 5
            curBlob = getNextAsnBlob(baseBlob); // gets 0xA1
            curBlob = getNextAsnBlob(baseBlob); // gets 0x02 msg type
            int msg_type = [[KerbInteger alloc] initWithObject:curBlob].KerbIntValue;
            if(msg_type == 0x1e){
                //this means we got msg-type of krb-error
                printf("Kerb-error: ");
                curBlob = getNextAsnBlob(baseBlob); // gets 0xA4
                curBlob = getNextAsnBlob(baseBlob); // gets 0x18 timestamp
                curBlob = getNextAsnBlob(baseBlob); // gets 0xA5
                curBlob = getNextAsnBlob(baseBlob); // gets 0x02 nonce
                curBlob = getNextAsnBlob(baseBlob); // gets 0xA6
                curBlob = getNextAsnBlob(baseBlob); // gets 0x02 error type
                printf("%d\n", getAsnIntegerBlob(curBlob));
                TGT.app1 = NULL;
                TGT.app29 = NULL;
                return TGT;
            }
            while(curBlob.type != 0xA4){
                curBlob = getNextAsnBlob(baseBlob);
            }
            TGT.app29 = [[KerbApp29 alloc] init];
            TGT.app29.cname = [[KerbCNamePrincipal alloc] initWithObject:carveAsnBlobObject(baseBlob)];
            curBlob = getNextAsnBlob(baseBlob); //gets 0xA5
            TGT.app1 = [[KerbApp1 alloc] initWithObject:carveAsnBlobObject(baseBlob)];
            //now we need to get to and parse out the encrypted part for more data to make our kribi
            curBlob = getNextAsnBlob(baseBlob); // should now be pointed to 0xA6 - encpart
            curBlob = getNextAsnBlob(baseBlob); // should now be pointing at 0x30 sequence
            curBlob = getNextAsnBlob(baseBlob); // 0xA0
            curBlob = getNextAsnBlob(baseBlob); // 0x02 enctype
            curBlob = getNextAsnBlob(baseBlob); // 0xA1
            curBlob = getNextAsnBlob(baseBlob); // 0x02 kvno
            curBlob = getNextAsnBlob(baseBlob); // 0xA2
            curBlob = getNextAsnBlob(baseBlob); // 0x04 the enc data as an octet string
            NSData* encdata = getAsnOctetStringBlob(curBlob);
            NSData* decryptedData = decryptKrbData(KRB5_KEYUSAGE_AS_REP_ENCPART, enc_type, encdata, hash);

            //printf("Decrypted encdata:\n%s\n", [decryptedData base64EncodedStringWithOptions:0].UTF8String);
            baseBlob = [[ASN1_Obj alloc] initWithType: ((Byte*)decryptedData.bytes)[0] Length:decryptedData.length Data:[[NSData alloc] initWithBytes:decryptedData.bytes length:decryptedData.length]];
            curBlob = getNextAsnBlob(baseBlob); // 0x79 Application 25
            parseASREPEncData(&TGT, baseBlob);
        }
        return TGT;
    }@catch(NSException* exception){
        printf("Error in parseASREP: %s\n", exception.reason.UTF8String);
        @throw exception;
    }
}
NSData* createPADataASReq(int enctype, NSString* hash){
    //Sequence (0x30)
    //  sequence (0x30)
    //    [1]
    //        INTEGER pdata-type (val 2 - krb5-padata-enc-timestamp)
    //    [2]
    //        OCTET STRING (0x04)
    //            Sequence (0x30)
    //                [0]
    //                    INTEGER enctype (18)
    //                [2]
    //                    OCTETSTRING (0x04) 56 bytes enc value
    //  sequence (0x30)
    //    [1] INTEGER (pdata-type 149) (KRB5-PDATA-REQ-ENC-PA-REP)
    //    [2] OCTET STRING (0 bytes, so 0x04 00)
    @try{
        NSData* plaintextDataToEncrypt = createPADataTimestamp();
        NSData* encryptedPAData = encryptKrbData(KRB5_KEYUSAGE_AS_REQ_PA_ENC_TS, enctype, plaintextDataToEncrypt, hash);
        ASN1_Obj* collapsed_pdatatype = createCollapsedAsnBasicType(0x02, minimizeAsnInteger(2));
        ASN1_Obj* collapsed_pdatatype2 = createCollapsedAsnBasicType(0x02, minimizeAsnInteger(149));
        ASN1_Obj* collapsedEnctype = createCollapsedAsnBasicType(0x02, minimizeAsnInteger(enctype));
        ASN1_Obj* collapsedEncryptedInnerOctet = createCollapsedAsnBasicType(0x04, encryptedPAData);
        //printf("\nencrypted octet string:\n%s\n", [collapsedEncryptedInnerOctet.data base64EncodedStringWithOptions:0].UTF8String);
        NSMutableArray<ASN1_Obj*> *sequence = [[NSMutableArray<ASN1_Obj*> alloc] init];
        [sequence insertObject:collapsedEnctype atIndex:0];
        [sequence insertObject:[ASN1_Obj alloc] atIndex:1]; //empty, skipped
        [sequence insertObject:collapsedEncryptedInnerOctet atIndex:2];
        ASN1_Obj* innerSequenceForOctetString = collapseAsnSequence(sequence);
        ASN1_Obj* itemTwoOctetString = createCollapsedAsnBasicType(0x04, innerSequenceForOctetString.data);
        //printf("\nOctetstring with sequence and encoded string:\n%s\n", [itemTwoOctetString.data base64EncodedStringWithOptions:0].UTF8String);
        [sequence removeAllObjects];
        [sequence insertObject:[ASN1_Obj alloc] atIndex:0]; //empty, skipped
        [sequence insertObject:collapsed_pdatatype atIndex:1];
        [sequence insertObject:itemTwoOctetString atIndex:2];
        ASN1_Obj* firstSubSequence = collapseAsnSequence(sequence);
        
        [sequence removeAllObjects];
        [sequence insertObject:[ASN1_Obj alloc] atIndex:0]; //empty, skipped
        [sequence insertObject:collapsed_pdatatype2 atIndex:1];
        ASN1_Obj* blankOctetString = createCollapsedAsnBasicType(0x04, [[NSData alloc] init]);
        [sequence insertObject:blankOctetString atIndex:2];
        ASN1_Obj* secondSubSequence = collapseAsnSequence(sequence);
        //printf("\nSequence with empty octet string:\n%s\n", [secondSubSequence.data base64EncodedStringWithOptions:0].UTF8String);
        NSData* twoSequences = appendAsnObj(firstSubSequence, secondSubSequence);
        ASN1_Obj* finalObj = createCollapsedAsnBasicType(0x30, twoSequences);
        return finalObj.data;
    }@catch(NSException* exception){
        printf("Error in createPADataASReq: %s\n", exception.reason.UTF8String);
        return NULL;
    }
}
NSData* createPADataTimestamp(){
    //sequence (0x30)
    //  [0] (0xA0)
    //    GeneralizedTime (timestamp of now)
    @try{
        NSDateFormatter *format = [[NSDateFormatter alloc] init];
        format.dateFormat = @"YYYYMMddHHmmss";
        format.timeZone = [NSTimeZone timeZoneWithAbbreviation:@"UTC"];
        NSMutableString* time = [[NSMutableString alloc] initWithString:[format stringFromDate:[NSDate date]]];
        [time appendString:@"Z"];
        //printf("%s\n", time.UTF8String);
        ASN1_Obj* collapsedTime = createCollapsedAsnBasicType(0x18, [[NSData alloc] initWithBytes:time.UTF8String length:time.length]);
        NSMutableArray<ASN1_Obj*> *sequence = [[NSMutableArray<ASN1_Obj*> alloc] init];
        [sequence insertObject:collapsedTime atIndex:0];
        ASN1_Obj* sequenceTwo = collapseAsnSequence(sequence);
        //printf("Data to be encrypted:\n%s\n", [doubleSequence.data base64EncodedStringWithOptions:0].UTF8String);
        return sequenceTwo.data;
    }@catch(NSException* exception){
        printf("[-] Error in createPADataTimestamp: %s\n", exception.reason.UTF8String);
        return NULL;
    }
}
NSData* createGeneralizedTime(int daysFromNow){
    @try{
        NSDateComponents* deltaComps = [[NSDateComponents alloc] init];
        [deltaComps setDay:daysFromNow];
        NSDate* tomorrow = [[NSCalendar currentCalendar] dateByAddingComponents:deltaComps toDate:[NSDate date] options:0];
        NSDateFormatter *format = [[NSDateFormatter alloc] init];
        format.dateFormat = @"YYYYMMddHHmmss";
        format.timeZone = [NSTimeZone timeZoneWithAbbreviation:@"UTC"];
        NSMutableString* time = [[NSMutableString alloc] initWithString:[format stringFromDate:tomorrow]];
        [time appendString:@"Z"];
        ASN1_Obj* collapsedTime = createCollapsedAsnBasicType(0x18, [[NSData alloc] initWithBytes:time.UTF8String length:time.length]);
        return collapsedTime.data;
    }@catch(NSException* exception){
        printf("[-] Error in createGeneralizedTime: %s\n", exception.reason.UTF8String);
        return NULL;
    }
}
NSData* dataFromHexString(NSString* hex){
    @try{
        const char *chars = [hex UTF8String];
        int i = 0, len = hex.length;
        
        NSMutableData *data = [NSMutableData dataWithCapacity:len / 2];
        char byteChars[3] = {'\0','\0','\0'};
        unsigned long wholeByte;

        while (i < len) {
            byteChars[0] = chars[i++];
            byteChars[1] = chars[i++];
            wholeByte = strtoul(byteChars, NULL, 16);
            [data appendBytes:&wholeByte length:1];
        }

        return data;
    }@catch(NSException* exception){
        printf("[-] Error in dataFromHexString: %s\n", exception.reason.UTF8String);
        return NULL;
    }
}
NSData* encryptKrbData(krb5_keyusage usage, int enctype, NSData* plaintextDataToEncrypt, NSString* hash){
    @try{
        NSData* result;
        krb5_context context;
        krb5_error_code ret;
        if (ret = krb5_init_context (&context) != 0){
            printKrbError(context,ret);
            return NULL;
        }
        krb5_keyblock key;
        NSData* hexContents = dataFromHexString(hash);
        
        key.length = hexContents.length;
        key.magic = KV5M_KEYBLOCK;//-1760647421;
        key.enctype = enctype;
        key.contents = malloc(key.length);
        
        memcpy(key.contents, hexContents.bytes, hexContents.length);
        
        size_t encrypt_length;
        //krb5_c_encrypt_length(krb5_context context, krb5_enctype enctype,size_t inputlen, size_t *length)
        ret = krb5_c_encrypt_length(context, enctype, plaintextDataToEncrypt.length, &encrypt_length);
        if(ret){
            printKrbError(context,ret);
            return NULL;
        }
        //alloc space in new krb5_data for encrypt_length amount of bytes
        krb5_enc_data encrypted_bytes;
        encrypted_bytes.magic = KV5M_KEYBLOCK;//-1760647421;
        encrypted_bytes.enctype = enctype;
        encrypted_bytes.ciphertext.length = encrypt_length;
        encrypted_bytes.ciphertext.data = malloc(encrypt_length);
        krb5_data plaintext_bytes;
        plaintext_bytes.data = plaintextDataToEncrypt.bytes;
        plaintext_bytes.length = plaintextDataToEncrypt.length;
        //krb5_c_encrypt(krb5_context context, const krb5_keyblock *key,krb5_keyusage usage, const krb5_data *cipher_state,const krb5_data *input, krb5_enc_data *output)
        ret = krb5_c_encrypt(context, &key, usage,NULL,&plaintext_bytes, &encrypted_bytes);
        if(ret){
            printKrbError(context,ret);
            return NULL;
        }
        result = [[NSData alloc] initWithBytes:encrypted_bytes.ciphertext.data length:encrypted_bytes.ciphertext.length];
        return result;
    }@catch(NSException* exception){
        printf("[-] Error in encryptKrbData: %s\n", exception.reason.UTF8String);
        return NULL;
    }
}
NSData* decryptKrbData(krb5_keyusage usage, int enctype, NSData* encryptedData, NSString* hash){
    @try{
        NSData* result;
        krb5_context context;
        krb5_error_code ret;
        if (ret = krb5_init_context (&context) != 0){
            printKrbError(context,ret);
            return NULL;
        }
        krb5_keyblock key;
        NSData* hexContents = dataFromHexString(hash);

        key.length = hexContents.length;
        key.magic = KV5M_KEYBLOCK;//-1760647421;
        key.enctype = enctype;
        key.contents = malloc(key.length);
        memcpy(key.contents, hexContents.bytes, hexContents.length);
        
        krb5_enc_data encrypted_bytes;
        encrypted_bytes.magic = KV5M_KEYBLOCK;//-1760647421;
        encrypted_bytes.enctype = enctype;
        encrypted_bytes.ciphertext.length = encryptedData.length;
        encrypted_bytes.ciphertext.data = encryptedData.bytes;
        krb5_data plaintext_bytes;
        plaintext_bytes.data = malloc(encryptedData.length);
        plaintext_bytes.length = encryptedData.length;
        //krb5_c_decrypt(krb5_context context, const krb5_keyblock *key,krb5_keyusage usage, const krb5_data *cipher_state,const krb5_enc_data *input, krb5_data *output)
        ret = krb5_c_decrypt(context, &key, usage, NULL, &encrypted_bytes, &plaintext_bytes);
        if(ret){
            printKrbError(context,ret);
            return NULL;
        }
        result = [[NSData alloc] initWithBytes:plaintext_bytes.data length:plaintext_bytes.length];
        return result;
    }@catch(NSException* exception){
        printf("[-] Error in decryptKrbData: %s\n", exception.reason.UTF8String);
        return NULL;
    }
}
void parseASREPEncData(Krb5Ticket* parsedTicket, ASN1_Obj* baseBlob){
    ASN1_Obj* curBlob;
    /*
     Application 25 (1 elem)
         SEQUENCE (12 elem)
           [0] (1 elem)
             SEQUENCE (2 elem)
               [0] (1 elem)
                 INTEGER 18
               [1] (1 elem)
                 OCTET STRING (32 byte) key
           [1] (1 elem)
             SEQUENCE (1 elem)
               SEQUENCE (2 elem)
                 [0] (1 elem)
                   INTEGER 0
                 [1] (1 elem)
                   GeneralizedTime 2019-10-24 05:22:07 UTC
           [2] (1 elem)
             INTEGER nonce
           [3] (1 elem)
             GeneralizedTime 2037-09-14 02:48:05 UTC
           [4] (1 elem)
             BIT STRING (32 bit) 01000000111000010000000000000000
           [5] (1 elem)
             GeneralizedTime 2019-10-24 05:22:07 UTC (auth)
           [6] (1 elem)
             GeneralizedTime 2019-10-24 05:22:07 UTC (start)
           [7] (1 elem)
             GeneralizedTime 2019-10-25 05:22:07 UTC (end)
           [8] (1 elem)
             GeneralizedTime 2019-10-31 05:22:07 UTC (renew)
           [9] (1 elem)
             GeneralString
           [10] (1 elem)
             SEQUENCE (2 elem)
               [0] (1 elem)
                 INTEGER 2
               [1] (1 elem)
                 SEQUENCE (2 elem)
                   GeneralString
                   GeneralString
           [12] (1 elem)
             SEQUENCE (1 elem)
               SEQUENCE (2 elem)
                 [1] (1 elem)
                   INTEGER 149
                 [2] (1 elem)
                   OCTET STRING (1 elem)
                     SEQUENCE (2 elem)
                       [0] (1 elem)
                         INTEGER 16
                       [1] (1 elem)
                         OCTET STRING (12 byte)
     */
    @try{
        curBlob = getNextAsnBlob(baseBlob); // sequence 0x30
        curBlob = getNextAsnBlob(baseBlob); // [0] 0xA0
        curBlob = getNextAsnBlob(baseBlob); // sequence
        curBlob = getNextAsnBlob(baseBlob); // [0]
        curBlob = getNextAsnBlob(baseBlob); // enc type
        parsedTicket->app29.enctype29 = [[KerbInteger alloc] initWithObject:curBlob];
        curBlob = getNextAsnBlob(baseBlob); // [1]
        curBlob = getNextAsnBlob(baseBlob); // key
        parsedTicket->app29.key = [[KerbOctetString alloc] initWithObject:curBlob];
        //parsedTicket->key = getAsnOctetStringBlob(curBlob);
        while(curBlob.type != 0xA4 ){
            curBlob = getNextAsnBlob(baseBlob); //get next blob
        }
        curBlob = getNextAsnBlob(baseBlob); // flags
        parsedTicket->app29.flags = [[KerbBitString alloc] initWithObject:curBlob];
        //parsedTicket->flags = getAsnBitString(curBlob);
        curBlob = getNextAsnBlob(baseBlob); // [5]
        curBlob = getNextAsnBlob(baseBlob);
        curBlob = getNextAsnBlob(baseBlob); // [6]
        curBlob = getNextAsnBlob(baseBlob); // start time
        //capture this value
        parsedTicket->app29.start = [[KerbGeneralizedTime alloc] initWithObject:curBlob];
        //parsedTicket->start_time = getAsnGenericStringBlob(curBlob).UTF8String;
        curBlob = getNextAsnBlob(baseBlob); // [7]
        curBlob = getNextAsnBlob(baseBlob); // end time
        // capture this value
        parsedTicket->app29.end = [[KerbGeneralizedTime alloc] initWithObject:curBlob];
        //parsedTicket->end_time = getAsnGenericStringBlob(curBlob).UTF8String;
        curBlob = getNextAsnBlob(baseBlob); // [8]
        curBlob = getNextAsnBlob(baseBlob); // renew time
        //capture this value
        parsedTicket->app29.till = [[KerbGeneralizedTime alloc] initWithObject:curBlob];
        //parsedTicket->renew_time = getAsnGenericStringBlob(curBlob).UTF8String;
        curBlob = getNextAsnBlob(baseBlob); // [9]
        curBlob = getNextAsnBlob(baseBlob); // 0x1B realm
        parsedTicket->app29.realm29 = [[KerbGenericString alloc] initWithObject:curBlob];
        curBlob = getNextAsnBlob(baseBlob); // [10]
        parsedTicket->app29.sname29 = [[KerbSNamePrincipal alloc] initWithObject:carveAsnBlobObject(baseBlob)];
    }@catch(NSException* exception){
        printf("[-] Error in parseASREPEncData: %s\n", exception.reason.UTF8String);
        @throw exception;
    }
}

NSData* createTGSREQ(Krb5Ticket TGT, NSString* service, bool kerberoasting, NSString* serviceDomain){
    /*
     *Application 12 (1 elem)
         SEQUENCE (4 elem)
           [1] (1 elem)
             INTEGER 5 (pvno) (static)
           [2] (1 elem)
             INTEGER 12 (krb-tgs-req)
           [3] (1 elem)
             SEQUENCE (1 elem)
               SEQUENCE (2 elem)
                 [1] (1 elem)
                   INTEGER 1 (krb5-padata-tgs-req)
                 [2] (1 elem)
                   OCTET STRING (1 elem) padata-value
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
           [4] (1 elem) req-body
             SEQUENCE (6 elem)
               [0] (1 elem)
                 BIT STRING (32 bit) 01000000000000010000000000000000 kdc-options
               [2] (1 elem)
                 GeneralString realm (serviceDomain)
               [3] (1 elem) sname
                 SEQUENCE (2 elem)
                   [0] (1 elem)
                     INTEGER 3 krb5-nt-srv-hst
                   [1] (1 elem)
                     SEQUENCE (2 elem)
                       GeneralString cifs
                       GeneralString hostname
               [5] (1 elem) til
                 GeneralizedTime 1970-01-01 00:00:00 UTC
               [7] (1 elem)
                 INTEGER 1227549756 nonce
               [8] (1 elem)
                 SEQUENCE (1 elem)
                   INTEGER 18 enctype
     */
    @try{
        KerbApp12* kerbapp12 = [[KerbApp12 alloc] initWithTicket:&TGT Service:service TargetDomain:serviceDomain Kerberoasting:kerberoasting];
        //return app12.data;
        return [kerbapp12 collapseToNSData];
    }@catch(NSException* exception){
        printf("[-] Error in createTGSReq: %s\n", exception.reason.UTF8String);
        @throw exception;
    }
}
Krb5Ticket parseTGSREP(NSData* tgsrep, Krb5Ticket TGT){
    //takes in the tgs response and the TGT that made the request, and parses out the response
    /*
    Application 13 (1 elem)
        SEQUENCE (6 elem)
          [0] (1 elem)
            INTEGER 5 pvno
          [1] (1 elem)
            INTEGER 13 krb-tgs-rep id
          [3] (1 elem)
            GeneralString (realm)
          [4] (1 elem)
            SEQUENCE (2 elem) cname
              [0] (1 elem)
                INTEGER 1
              [1] (1 elem)
                SEQUENCE (1 elem)
                  GeneralString (user account that did the request)
          [5] (1 elem)
            Application 1 (1 elem)
              SEQUENCE (4 elem)
                [0] (1 elem)
                  INTEGER 5 tkt-vno
                [1] (1 elem)
                  GeneralString realm
                [2] (1 elem)
                  SEQUENCE (2 elem)
                    [0] (1 elem)
                      INTEGER 2 krb5-nt-srv-inst
                    [1] (1 elem)
                      SEQUENCE (2 elem)
                        GeneralString account
                        GeneralString computer
                [3] (1 elem)
                  SEQUENCE (3 elem)
                    [0] (1 elem)
                      INTEGER 23 enctype
                    [1] (1 elem)
                      INTEGER 214 kvno
                    [2] (1 elem)
                      OCTET STRING (1071 byte) 
          [6] (1 elem)
            SEQUENCE (2 elem)
              [0] (1 elem)
                INTEGER 18 enctype
              [2] (1 elem)
                OCTET STRING (250 byte) **encdata
     
     
    **encdata:
     Application 26 (1 elem)
     SEQUENCE (10 elem)
       [0] (1 elem)
         SEQUENCE (2 elem)
           [0] (1 elem)
             INTEGER 23 enctype
           [1] (1 elem)
             OCTET STRING (16 byte) (key?)
       [1] (1 elem)
         SEQUENCE (1 elem)
           SEQUENCE (2 elem)
             [0] (1 elem)
               INTEGER 0
             [1] (1 elem)
               GeneralizedTime 2019-10-27 22:04:20 UTC
       [2] (1 elem)
         INTEGER 276925316 (nonce)
       [4] (1 elem)
         BIT STRING (32 bit) 00000000101001010000000000000000 (flags)
       [5] (1 elem)
         GeneralizedTime 2019-10-27 19:46:27 UTC (auth)
       [6] (1 elem)
         GeneralizedTime 2019-10-27 22:04:20 UTC (start)
       [7] (1 elem)
         GeneralizedTime 2019-10-28 08:04:20 UTC (end)
       [8] (1 elem)
         GeneralizedTime 2019-11-03 19:46:27 UTC (till/renew)
       [9] (1 elem)
         GeneralString (realm)
       [10] (1 elem)
         SEQUENCE (2 elem) (sname)
           [0] (1 elem)
             INTEGER 2
           [1] (1 elem)
             SEQUENCE (2 elem)
               GeneralString
               GeneralString
     */
    Krb5Ticket sTicket; //you get back a service ticket (sticket), not a tgs
    printf("[+] Parsing TGS-REP\n");
    @try{
        ASN1_Obj* baseObject = [[ASN1_Obj alloc] initWithType:((Byte*)tgsrep.bytes)[0] Length:tgsrep.length Data:tgsrep];
        ASN1_Obj* curObj = getNextAsnBlob(baseObject);
        curObj = getNextAsnBlob(baseObject); // gets 0x30
        curObj = getNextAsnBlob(baseObject); // gets 0xA0
        curObj = getNextAsnBlob(baseObject); // gets 0x02 (pvno 5)
        curObj = getNextAsnBlob(baseObject); // gets 0xA1
        curObj = getNextAsnBlob(baseObject); // gets 0x02 (krb-tgs-rep val 13)
        int msg_type = [[KerbInteger alloc] initWithObject:curObj].KerbIntValue;
        if(msg_type == 0x1e){
            //this means we got msg-type of krb-error
            printf("[-] Kerb-error: ");
            curObj = getNextAsnBlob(baseObject); // gets 0xA4
            curObj = getNextAsnBlob(baseObject); // gets 0x18 timestamp
            curObj = getNextAsnBlob(baseObject); // gets 0xA5
            curObj = getNextAsnBlob(baseObject); // gets 0x02 nonce
            curObj = getNextAsnBlob(baseObject); // gets 0xA6
            curObj = getNextAsnBlob(baseObject); // gets 0x02 error type
            printf("0x%02X\n", getAsnIntegerBlob(curObj));
            sTicket.app1 = NULL;
            sTicket.app29 = NULL;
            return sTicket;
        }
        sTicket.app29 = [[KerbApp29 alloc] init];
        curObj = getNextAsnBlob(baseObject); // gets 0xA3
        curObj = getNextAsnBlob(baseObject); // gets 0x1B (realm)
        sTicket.app29.realm29 = [[KerbGenericString alloc] initWithObject:curObj];
        printf("Client Domain: %s\n", sTicket.app29.realm29.KerbGenStringvalue.UTF8String);
        curObj = getNextAsnBlob(baseObject); // gets 0xA4
        KerbCNamePrincipal* cname = [[KerbCNamePrincipal alloc] initWithObject:carveAsnBlobObject(baseObject)];
        sTicket.app29.cname = cname;
        printf("Requesting account: %s\n", cname.username.KerbGenStringvalue.UTF8String);
        curObj = getNextAsnBlob(baseObject); // gets 0xA5
        sTicket.app1 = [[KerbApp1 alloc] initWithObject:carveAsnBlobObject(baseObject)];
        printf("Requested Service: %s\n", [sTicket.app1.sname getNSString].UTF8String);
        printf("Ticket Encryption: %d\n", sTicket.app1.enctype.KerbIntValue);
        curObj = getNextAsnBlob(baseObject); // gets 0xA6
        curObj = getNextAsnBlob(baseObject); // gets 0x30
        curObj = getNextAsnBlob(baseObject); // gets 0xA0
        curObj = getNextAsnBlob(baseObject); // gets 0x02 enctype
        curObj = getNextAsnBlob(baseObject); // gets 0xA2
        curObj = getNextAsnBlob(baseObject); // gets 0x04 encdata
        NSData* encdata = [[KerbOctetString alloc] initWithObject:curObj].KerbOctetvalue;
        NSData* decryptedData = decryptKrbData(KRB5_KEYUSAGE_TGS_REP_ENCPART_SESSKEY, 18, encdata, [TGT.app29.key getHexValue]);
        //printf("Decrypted TGS-REP Section:\n%s\n", [decryptedData base64EncodedStringWithOptions:0].UTF8String);
        //now parse out the encrypted pieces to finish the ticket
        baseObject = [[ASN1_Obj alloc] initWithType:0x7A Length:decryptedData.length Data:decryptedData];
        curObj = getNextAsnBlob(baseObject);
        curObj = getNextAsnBlob(baseObject); // gets 0x30
        curObj = getNextAsnBlob(baseObject); // gets 0xA0
        curObj = getNextAsnBlob(baseObject); // gets 0x30
        curObj = getNextAsnBlob(baseObject); // gets 0xA0
        curObj = getNextAsnBlob(baseObject); // gets 0x02 enctype
        sTicket.app29.enctype29 = [[KerbInteger alloc] initWithObject:curObj];
        curObj = getNextAsnBlob(baseObject); // gets 0xA1
        curObj = getNextAsnBlob(baseObject); // gets 0x04 key
        sTicket.app29.key = [[KerbOctetString alloc] initWithObject:curObj];
        curObj = getNextAsnBlob(baseObject); // gets 0xA1
        curObj = getNextAsnBlob(baseObject); // gets 0x30
        curObj = getNextAsnBlob(baseObject); // gets 0x30
        curObj = getNextAsnBlob(baseObject); // gets 0xA0
        curObj = getNextAsnBlob(baseObject); // gets 0x02 int zero
        curObj = getNextAsnBlob(baseObject); // gets 0xA1
        curObj = getNextAsnBlob(baseObject); // gets 0x18 generalized time for something
        curObj = getNextAsnBlob(baseObject); // gets 0xA2
        curObj = getNextAsnBlob(baseObject); // gets 0x02 nonce
        curObj = getNextAsnBlob(baseObject); // gets 0xA4
        curObj = getNextAsnBlob(baseObject); // gets 0x30 flags
        sTicket.app29.flags = [[KerbBitString alloc] initWithObject:curObj];
        curObj = getNextAsnBlob(baseObject); // gets 0xA5
        curObj = getNextAsnBlob(baseObject); // gets 0x18 generalized time of auth
        curObj = getNextAsnBlob(baseObject); // gets 0xA6
        curObj = getNextAsnBlob(baseObject); // gets 0x18 generalized time of start
        sTicket.app29.start = [[KerbGeneralizedTime alloc] initWithObject:curObj];
        curObj = getNextAsnBlob(baseObject); // gets 0xA7
        curObj = getNextAsnBlob(baseObject); // gets 0x18 generalized time of end
        sTicket.app29.end = [[KerbGeneralizedTime alloc] initWithObject:curObj];
        curObj = getNextAsnBlob(baseObject); // gets 0xA8
        curObj = getNextAsnBlob(baseObject); // gets 0x18 generalized time of renew
        sTicket.app29.till = [[KerbGeneralizedTime alloc] initWithObject:curObj];
        curObj = getNextAsnBlob(baseObject); // gets 0xA9
        curObj = getNextAsnBlob(baseObject); // gets 0x1B realm
        curObj = getNextAsnBlob(baseObject); // gets 0xAA
        sTicket.app29.sname29 = [[KerbSNamePrincipal alloc] initWithObject:carveAsnBlobObject(baseObject)];
        return sTicket;
    }@catch(NSException* exception){
        printf("[-] Error in parseTGSREP: %s\n", exception.reason.UTF8String);
        @throw exception;
    }
}

NSData* createS4U2SelfReq(Krb5Ticket TGT, NSString* targetUser){
    if(![targetUser containsString:@"@"]){
        targetUser = [targetUser stringByAppendingFormat:@"@%s", TGT.app1.realm.KerbGenStringvalue.UTF8String];
    }
    KerbApp12* S4U2SelfRequest = [[KerbApp12 alloc] initWithTicket:&TGT TargetUser:targetUser TargetDomain:TGT.app1.realm.KerbGenStringvalue];
    return [S4U2SelfRequest collapseToNSData];
}
NSData* createS4U2ProxyReq(Krb5Ticket sTicket, NSString* spn, NSString* spnDomain, NSData* innerTicket){
    KerbApp12* S4U2ProxyRequest = [[KerbApp12 alloc] initForProxyWithTicket:&sTicket Service:spn TargetDomain:spnDomain InnerTicket:innerTicket ];
    return [S4U2ProxyRequest collapseToNSData];
}

