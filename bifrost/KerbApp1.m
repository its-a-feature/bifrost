//
//  KerbApp1.m
//  bifrost
//
//  Created by @its_a_feature_ on 10/14/19.
//  Copyright © 2019 Cody Thomas (@its_a_feature_). All rights reserved.
//

#import <Foundation/Foundation.h>
#include "KerbApp1.h"

@implementation KerbApp1
/*
 Application 1 (1 elem)                                         0x61 [length bytes]
     SEQUENCE (4 elem)                                          0x30 [length bytes]
        [0] (1 elem)                                            0xA0 [length bytes]
            INTEGER tkt-vno (5 - static)                        0x02 [length bytes] [value]
        [1] (1 elem)                                            0xA1 [length bytes]
            GeneralString (realm)                               0x1B [length bytes] [value]
        [2] (1 elem) sname                                      0xA2 [length bytes]
            SEQUENCE (2 elem)                                   0x30 [length bytes]             - start KerbSNamePrincipal
                [0] (1 elem)                                    0xA0 [length bytes]
                    INTEGER krb5-nt-srv-inst (2 - static)       0x02 [length bytes] [value]
                [1] (1 elem)                                    0xA1 [length bytes]
                    SEQUENCE (2 elem)                           0x30 [length bytes]
                        GeneralString (krbtgt)                  0x1B [length bytes] [value]
                        GeneralString (domain)                  0x1B [length bytes] [value]     - end  KerbSNamePrincipal
        [3] (1 elem)                                            0xA3 [length bytes]
            SEQUENCE (3 elem)                                   0x30 [length bytes]
                [0] (1 elem)                                    0xA0 [length bytes]
                    INTEGER enctype (18)                        0x02 [length bytes] [value]
                [1] (1 elem)                                    0xA1 [length bytes]
                    INTEGER kvno (12 )                          0x02 [length bytes] [value]
                [2] (1 elem)                                    0xA2 [length bytes]
                    OCTETSTRING encoded data                    0x04 [length bytes] [value]
 */
KerbInteger* tkt_vno;
KerbGenericString* realm;
KerbSNamePrincipal* sname;
KerbInteger* enctype;
KerbInteger* kvno;
KerbOctetString* encdata;
-(id)initWithObject:(ASN1_Obj*)baseObject{
    if(self = [super init]){
        //given an ASN1 blob of the above structure, parse out the necessary information
        //assuming that baseObject points to application 1
        ASN1_Obj* curBlob;
        if(baseObject.type == 0x61 && baseObject.length == baseObject.data.length){
            //this means we were just given a raw blob, not actually adjusted for data to point to the real data
            //so we move the analysis forward one chunk so that baseObject.data points to the actual data, not the start of the asn1 blob
            curBlob = getNextAsnBlob(baseObject); //get everything aligned.
        }
        curBlob = getNextAsnBlob(baseObject); // gets 0x30
        curBlob = getNextAsnBlob(baseObject); // gets 0xA0
        curBlob = getNextAsnBlob(baseObject); //gets tkt-vno
        self.tkt_vno = [[KerbInteger alloc] initWithObject:curBlob];
        curBlob = getNextAsnBlob(baseObject); //gets 0xA1
        curBlob = getNextAsnBlob(baseObject); //gets realm
        self.realm = [[KerbGenericString alloc] initWithValue:getAsnGenericStringBlob(curBlob)];
        curBlob = getNextAsnBlob(baseObject); //gets 0xA2, baseObj points to next element which is start of sname
        ASN1_Obj* snameBlob = carveAsnBlobObject(baseObject); //carves out sequence blob and moves baseObject forward past it
        self.sname = [[KerbSNamePrincipal alloc] initWithObject:snameBlob];
        curBlob = getNextAsnBlob(baseObject); //gets 0xA3
        curBlob = getNextAsnBlob(baseObject); //gets 0x30
        curBlob = getNextAsnBlob(baseObject); //gets 0xA0
        curBlob = getNextAsnBlob(baseObject); //gets enctype integer
        self.enctype = [[KerbInteger alloc] initWithObject:curBlob];
        curBlob = getNextAsnBlob(baseObject); //gets 0xA1
        if(curBlob.type == 0xA1){ // apparently not always guaranteed to get this element back
            curBlob = getNextAsnBlob(baseObject); // gets kvno integer
            self.kvno = [[KerbInteger alloc] initWithObject:curBlob];
            curBlob = getNextAsnBlob(baseObject); //gets 0xA2
        }else{
            self.kvno = [[KerbInteger alloc] initWithObject:0]; //stopgap measure
        }
        
        curBlob = getNextAsnBlob(baseObject); // gets encdata
        self.encdata = [[KerbOctetString alloc] initWithObject:curBlob];
    }
    return self;
}
-(id)initWithRealm:(NSString*)realm SName:(KerbSNamePrincipal*)sname Enctype:(int)enctype Encdata:(NSData*)encdata{
    if(self = [super init]){
        self.tkt_vno = [[KerbInteger alloc] initWithValue:5];
        self.realm = [[KerbGenericString alloc] initWithValue:realm];
        self.sname = sname;
        self.enctype  = [[KerbInteger alloc] initWithValue:enctype];
        self.encdata = [[KerbOctetString alloc] initWithValue:encdata];
    }
    return self;
}
-(id)initWithRealm:(NSString*)realm Service:(NSString*)service Computer:(NSString*)computer Enctype:(int)enctype Encdata:(NSData*)encdata{
    if(self = [super init]){
        self.tkt_vno = [[KerbInteger alloc] initWithValue:5];
        self.kvno = [[KerbInteger alloc] initWithValue:12];
        self.realm = [[KerbGenericString alloc] initWithValue:realm];
        self.sname = [[KerbSNamePrincipal alloc] initWithValueAccount:service Domain:computer];
        self.enctype  = [[KerbInteger alloc] initWithValue:enctype];
        self.encdata = [[KerbOctetString alloc] initWithValue:encdata];
    }
    return self;
}
-(NSData*)collapseToNSData{
    return [self collapseToAsnObject].data;
}
-(ASN1_Obj*)collapseToAsnObject{
    KerbSequence* sequence = [[KerbSequence alloc] initWithEmpty];
    [sequence addAsn:[self.tkt_vno collapseToAsnObject] inSpot:0];
    [sequence addAsn:[self.realm collapseToAsnObject] inSpot:1];
    [sequence addAsn:[self.sname collapseToAsnObject] inSpot:2];
    //now to create the bottom sequence
    KerbSequence* bottomSequence = [[KerbSequence alloc] initWithEmpty];
    [bottomSequence addAsn:[self.enctype collapseToAsnObject] inSpot:0];
    [bottomSequence addAsn:[self.kvno collapseToAsnObject] inSpot:1];
    [bottomSequence addAsn:[self.encdata collapseToAsnObject] inSpot:2];
    
    [sequence addAsn:[bottomSequence collapseToAsnObject] inSpot:3];
    
    ASN1_Obj* application = createCollapsedAsnBasicType(0x61, [sequence collapseToNSData]);
    return application;
}
@end
