//
//  KerbApp29.m
//  bifrost
//
//  Created by @its_a_feature_ on 10/14/19.
//  Copyright © 2019 Cody Thomas (@its_a_feature_). All rights reserved.
//

#import <Foundation/Foundation.h>
#import "KerbApp29.h"

@implementation KerbApp29
/*
Application 29 (1 elem)                                    0x7D [length bytes]
    SEQUENCE (1 elem)                                      0x30 [length bytes]
      [0] (1 elem)                                         0xA0 [length bytes]
        SEQUENCE (1 elem)                                  0x30 [length bytes]
          SEQUENCE (9 elem)                                0x30 [length bytes]
            [0] (1 elem)                                   0xA0 [length bytes]
              SEQUENCE (2 elem)                            0x30 [length bytes]
                [0] (1 elem)                               0xA0 [length bytes]
                  INTEGER 18  enctype                      0x02 [length bytes] [value]
                [1] (1 elem)                               0xA1 [length bytes]
                  OCTET STRING (32 byte) key               0x04 [length bytes] [value]
            [1] (1 elem)                                   0xA1 [length bytes]
              GeneralString  realm                         0x1B [length bytes] [value]
            [2] (1 elem)                                   0xA2 [length bytes]
              SEQUENCE (2 elem)                            0x30 [length bytes]           - start CNamePrincipal
                [0] (1 elem)                               0xA0 [length bytes]
                  INTEGER 1                                0x02 [length bytes] [value]
                [1] (1 elem)                               0xA1 [length bytes]
                  SEQUENCE (1 elem)                        0x30 [length bytes]
                    GeneralString  client principal        0x1B [length bytes] [value]   - end   CNamePrincipal
            [3] (1 elem)                                   0xA3 [length bytes]
              BIT STRING (32 bit) flags                    0x03 [length bytes] [value]
            [5] (1 elem)                                   0xA5 [length bytes]
              GeneralizedTime 2019-10-18 17:39:42 UTC      0x18 [length bytes] [value] (start)
            [6] (1 elem)                                   0xA6 [length bytes]
              GeneralizedTime 2019-10-19 03:39:42 UTC      0x18 [length bytes] [value] (end)
            [7] (1 elem)                                   0xA7 [length bytes]
              GeneralizedTime 2019-10-25 17:38:49 UTC      0x18 [length bytes] [value] (renew/till)
            [8] (1 elem)                                   0xA8 [length bytes]
              GeneralString  realm                         0x1B [length bytes] [value]
            [9] (1 elem)                                   0xA9 [length bytes]
              SEQUENCE (2 elem)                            0x30 [length bytes]           - start SNamePrincipal
                [0] (1 elem)                               0xA0 [length bytes]
                  INTEGER 2                                0x02 [length bytes] [value]
                [1] (1 elem)                               0xA1 [length bytes]
                  SEQUENCE (2 elem)                        0x30 [length bytes]
                    GeneralString                          0x1B [length bytes] [value]
                    GeneralString                          0x1B [length bytes] [value]  - end SNamePrincipal
*/
KerbInteger* enctype29;
KerbOctetString* key;
KerbGenericString* realm29;
KerbCNamePrincipal* cname;
KerbBitString* flags;
KerbGeneralizedTime* start;
KerbGeneralizedTime* end;
KerbGeneralizedTime* till;
KerbSNamePrincipal* sname29;

-(id)initWithObject:(ASN1_Obj*)baseObject{
    if(self = [super init]){
        //given an ASN1 blob of the above structure, parse out the necessary information
        //assuming that baseObject points to application 29
        ASN1_Obj* curBlob;
        if(baseObject.type == 0x7D && baseObject.length == baseObject.data.length){
            //this means we were just given a raw blob, not actually adjusted for data to point to the real data
            //so we move the analysis forward one chunk so that baseObject.data points to the actual data, not the start of the asn1 blob
            curBlob = getNextAsnBlob(baseObject); //get everything aligned.
        }
        curBlob = getNextAsnBlob(baseObject); // gets 0x30
        curBlob = getNextAsnBlob(baseObject); // gets 0xA0
        curBlob = getNextAsnBlob(baseObject); // gets 0x30
        curBlob = getNextAsnBlob(baseObject); // gets 0x30
        curBlob = getNextAsnBlob(baseObject); // gets 0xA0
        curBlob = getNextAsnBlob(baseObject); // gets 0x30
        curBlob = getNextAsnBlob(baseObject); // gets 0xA0
        curBlob = getNextAsnBlob(baseObject); // gets 0x02 enctype
        self.enctype29 = [[KerbInteger alloc] initWithObject:curBlob];
        curBlob = getNextAsnBlob(baseObject); // gets 0xA1
        curBlob = getNextAsnBlob(baseObject); // gets 0x04 key
        self.key = [[KerbOctetString alloc] initWithObject:curBlob];
        curBlob = getNextAsnBlob(baseObject); // gets 0xA1
        curBlob = getNextAsnBlob(baseObject); // gets 0x1B realm
        self.realm29 = [[KerbGenericString alloc] initWithObject:curBlob];
        curBlob = getNextAsnBlob(baseObject); // gets 0xA2, baseObject now points to start of sequence for cnameprincipal
        ASN1_Obj* cnameBlob = carveAsnBlobObject(baseObject); //carves out sequence blob and moves baseObject forward past it
        self.cname = [[KerbCNamePrincipal alloc] initWithObject:cnameBlob];
        curBlob = getNextAsnBlob(baseObject); // gets 0xA3
        curBlob = getNextAsnBlob(baseObject); // gets 0x03 flags
        self.flags = [[KerbBitString alloc] initWithObject:curBlob];
        curBlob = getNextAsnBlob(baseObject); // gets 0xA5
        curBlob = getNextAsnBlob(baseObject); // gets 0x18 start
        self.start = [[KerbGeneralizedTime alloc] initWithObject:curBlob];
        curBlob = getNextAsnBlob(baseObject); // gets 0xA6
        curBlob = getNextAsnBlob(baseObject); // gets 0x18 end
        self.end = [[KerbGeneralizedTime alloc] initWithObject:curBlob];
        curBlob = getNextAsnBlob(baseObject); // gets 0xA7
        curBlob = getNextAsnBlob(baseObject); // gets 0x18 till
        self.till = [[KerbGeneralizedTime alloc] initWithObject:curBlob];
        curBlob = getNextAsnBlob(baseObject); // gets 0xA8
        curBlob = getNextAsnBlob(baseObject); // gets 0x1B realm again
        curBlob = getNextAsnBlob(baseObject); // gets 0xA9, baseObject now points to start of sequence for snameprincipal
        ASN1_Obj* snameBlob = carveAsnBlobObject(baseObject);
        self.sname29 = [[KerbSNamePrincipal alloc] initWithObject:snameBlob];
    }
    return self;
}
-(NSData*)collapseToNSData{
    return [self collapseToAsnObject].data;
}
-(ASN1_Obj*)collapseToAsnObject{
    KerbSequence* sequence = [[KerbSequence alloc] initWithEmpty];
    //now to create the sequence with the key
    KerbSequence* keySequence = [[KerbSequence alloc] initWithEmpty];
    [keySequence addAsn:[self.enctype29 collapseToAsnObject] inSpot:0];
    [keySequence addAsn:[self.key collapseToAsnObject] inSpot:1];
    
    [sequence addAsn:[keySequence collapseToAsnObject] inSpot:0];
    [sequence addAsn:[self.realm29 collapseToAsnObject] inSpot:1];
    [sequence addAsn:[self.cname collapseToAsnObject] inSpot:2];
    [sequence addAsn:[self.flags collapseToAsnObject] inSpot:3];
    [sequence addEmptyinSpot:4];
    [sequence addAsn:[self.start collapseToAsnObject] inSpot:5];
    [sequence addAsn:[self.end collapseToAsnObject] inSpot:6];
    [sequence addAsn:[self.till collapseToAsnObject] inSpot:7];
    [sequence addAsn:[self.realm29 collapseToAsnObject] inSpot:8];
    [sequence addAsn:[self.sname29 collapseToAsnObject] inSpot:9];
    
    ASN1_Obj* collapsedNine = [sequence collapseToAsnObject];
    //now we have to do all of the odd outer layer additions
    ASN1_Obj* collapsedNine1 = createCollapsedAsnBasicType(0x30, collapsedNine.data);
    ASN1_Obj* collapsedNine12 = createCollapsedAsnBasicType(0xA1, collapsedNine1.data);
    ASN1_Obj* collapsedNine123 = createCollapsedAsnBasicType(0x30, collapsedNine12.data);
    ASN1_Obj* application = createCollapsedAsnBasicType(0x7D, collapsedNine123.data);
    return application;
}
@end
