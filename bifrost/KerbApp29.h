//
//  KerbApp29.h
//  bifrost
//
//  Created by @its_a_feature_ on 10/14/19.
//  Copyright © 2019 Cody Thomas (@its_a_feature_). All rights reserved.
//

#import "KerbInteger.h"
#import "KerbOctetString.h"
#import "KerbGenericString.h"
#import "KerbBitString.h"
#import "KerbGeneralizedTime.h"
#import "KerbSequence.h"
#import "KerbCNamePrincipal.h"
#import "KerbSNamePrincipal.h"
@interface KerbApp29 : NSObject
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
                   INTEGER 1   static value                 0x02 [length bytes] [value]
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
               GeneralString  realm                         0x1B [length bytees] [value]
             [9] (1 elem)                                   0xA9 [length bytes]
               SEQUENCE (2 elem)                            0x30 [length bytes]           - start SNamePrincipal
                 [0] (1 elem)                               0xA0 [length bytes]
                   INTEGER 2                                0x02 [length bytes] [value]
                 [1] (1 elem)                               0xA1 [length bytes]
                   SEQUENCE (2 elem)                        0x30 [length bytes]
                     GeneralString                          0x1B [length bytes] [value]
                     GeneralString                          0x1B [length bytes] [value]  - end SNamePrincipal
 */
@property KerbInteger* enctype29;
@property KerbOctetString* key;
@property KerbGenericString* realm29;
@property KerbCNamePrincipal* cname;
@property KerbBitString* flags;
@property KerbGeneralizedTime* start;
@property KerbGeneralizedTime* end;
@property KerbGeneralizedTime* till;
@property KerbSNamePrincipal* sname29;

-(id)initWithObject:(ASN1_Obj*)baseObject; //parse it yourself into the values
-(NSData*)collapseToNSData;
-(ASN1_Obj*)collapseToAsnObject;
@end

