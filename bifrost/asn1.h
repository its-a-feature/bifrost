//
//  asn1.h
//  bifrost
//
//  Created by @its_a_feature_ on 10/14/19.
//  Copyright © 2019 Cody Thomas (@its_a_feature_). All rights reserved.
//
#import <Foundation/Foundation.h>
@interface ASN1_Obj : NSObject
@property (nonatomic) Byte type;
@property (nonatomic) uint32_t length; //length of the whole ASN1 object
@property (nonatomic, strong) NSData *data; //length here is specifically the length of the bytes in the value

-(id)initWithType:(Byte)type Length:(uint32_t)length Data:(NSData*)data;
@end

ASN1_Obj* getNextAsnBlob(ASN1_Obj* blob);
NSData* carveAsnBlob(ASN1_Obj* blob);
ASN1_Obj* carveAsnBlobObject(ASN1_Obj* blob);
int getAsnIntegerBlob(ASN1_Obj* blob);
NSString* getAsnGenericStringBlob(ASN1_Obj* blob);
NSData* getAsnOctetStringBlob(ASN1_Obj* blob);
NSData* getAsnLengthBytes(NSData* blob);
ASN1_Obj* collapseAsnBasicType(ASN1_Obj* baseBlob);
bool isContainerObject(Byte type);
NSData* minimizeAsnInteger(int value);
NSData* appendAsnObj(ASN1_Obj* first, ASN1_Obj* second);
ASN1_Obj* collapseAsnSequence(NSArray<ASN1_Obj*> *sequence);
ASN1_Obj* createCollapsedAsnBasicType(Byte type, NSData* data);
NSData* createAsnBitString(int value);
int getAsnBitString(ASN1_Obj* obj);

