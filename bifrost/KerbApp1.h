//
//  KerbApp1.h
//  bifrost
//
//  Created by @its_a_feature_ on 10/14/19.
//  Copyright © 2019 Cody Thomas (@its_a_feature_). All rights reserved.
//
#import "KerbInteger.h"
#import "KerbGenericString.h"
#import "KerbSNamePrincipal.h"
#import "KerbOctetString.h"
#import "asn1.h"

@interface KerbApp1 : NSObject
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
@property KerbInteger* tkt_vno;
@property KerbGenericString* realm;
@property KerbSNamePrincipal* sname;
@property KerbInteger* enctype;
@property KerbInteger* kvno;
@property KerbOctetString* encdata;
-(id)initWithObject:(ASN1_Obj*)baseObject; //parse it yourself into the values
-(id)initWithRealm:(NSString*)realm SName:(KerbSNamePrincipal*)sname Enctype:(int)enctype Encdata:(NSData*)encdata;
-(NSData*)collapseToNSData;
-(ASN1_Obj*)collapseToAsnObject;
@end

