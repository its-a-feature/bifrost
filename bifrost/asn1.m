//
//  asn1.m
//  bifrost
//
//  Created by @its_a_feature_ on 10/14/19.
//  Copyright © 2019 Cody Thomas (@its_a_feature_). All rights reserved.
//

#import <Foundation/Foundation.h>
#include "asn1.h"

@implementation ASN1_Obj
-(id)initWithType:(Byte)type Length:(uint32_t)length Data:(NSData*)data{
    if(self = [super init]){
        self.type = type;
        self.length = length;
        self.data = data;
    }
    return self;
}
@end

ASN1_Obj* getNextAsnBlob(ASN1_Obj* blob){
    //given the start of a blob, return proper blob with the right data for the current item in the ASN1
    ASN1_Obj* new_blob = [ASN1_Obj alloc];
    @try{
        //printf("Current base length: %d\n", blob.data.length);
        new_blob.type = ((Byte*)blob.data.bytes)[0]; // type is the first byte
        uint rest_length = 0; //final length of the data
        uint length_bytes = 0;
        if( ((Byte*)blob.data.bytes)[1] > 0x7F ){
            //this means we need to look at the next sequence of bytes to get full length
            length_bytes = ((Byte*)blob.data.bytes)[1] & 0x7F;
            for(int i = 0; i < length_bytes; i++){
                rest_length <<= 8;
                rest_length |= ((Byte*)blob.data.bytes)[2 + i];
            }
            new_blob.length = rest_length + 2 + length_bytes; //include the type byte and size bytes, this is _total_ length
            //make sure the bytes we want to parse out actually exist, otherwise throw an error
            if(length_bytes + 2 + rest_length > blob.data.length){
                printf("[-] Error: trying to move outside of blob range in getNextAsnBlob while creating new blob\n");
                @throw [[NSException alloc] initWithName:@"Future out of bounds" reason:@"Future out of bounds" userInfo:NULL];
            }
            new_blob.data = [[NSData alloc] initWithBytes:((Byte*)blob.data.bytes) + 2 + length_bytes length:rest_length ];
            length_bytes += 1; // account for the 0x8* byte
        }else{
            length_bytes = 1;
            rest_length = ((Byte*)blob.data.bytes)[1] & 0xFF;
            new_blob.length =  rest_length + 2; //include type byte and size byte, this is _total_ length
            if(2 + rest_length > blob.data.length){
                printf("[-] Error: trying to move outside of blob range in getNextAsnBlob while creating new blob\n");
                @throw [[NSException alloc] initWithName:@"Future out of bounds" reason:@"Future out of bounds" userInfo:NULL];
            }
            new_blob.data = [[NSData alloc] initWithBytes:((Byte*)blob.data.bytes) + 2 length:rest_length ];
        }
        // new_blob.length is the total length of the next ASN1 object including type byte and length bytes
        // new_blob.data is the actual contents of the thing indicated by the type
        if(isContainerObject(new_blob.type)){
            //just move forward the size of the type + size bytes, which is 1 + length_bytes
            blob.length = blob.length - 1 - length_bytes;
            //blob.data = [[NSData alloc] initWithData:[blob.data subdataWithRange:NSMakeRange(1 + length_bytes, blob.length)]];
            if(1 + length_bytes > blob.data.length){
                printf("[-] Error: trying to move outside of blob range in getNextAsnBlob while moving base forward\n");
                @throw [[NSException alloc] initWithName:@"Future out of bounds" reason:@"Future out of bounds" userInfo:NULL];
            }
            blob.data = [[NSData alloc] initWithData:[blob.data subdataWithRange:NSMakeRange(1 + length_bytes, blob.data.length - 1 - length_bytes)]];
        }else{
            // move forward the size of the type + size bytes + length of the content, which is the total length of the new blob
            //printf("old blob length: %d\n", blob.length);
            blob.length = blob.length - new_blob.length;
            //printf("New blob length: %d\nBlob length: %d\n", new_blob.length, blob.length);
            //blob.data = [[NSData alloc] initWithData:[blob.data subdataWithRange:NSMakeRange(new_blob.length, blob.length)]];
            if(new_blob.length > blob.data.length){
                printf("[-] Error: trying to move outside of blob range in getNextAsnBlob while moving base forward\n");
                @throw [[NSException alloc] initWithName:@"Future out of bounds" reason:@"Future out of bounds" userInfo:NULL];
            }
            blob.data = [[NSData alloc] initWithData:[blob.data subdataWithRange:NSMakeRange(new_blob.length, blob.data.length - new_blob.length)]];
        }
        return new_blob;
    }@catch(NSException* exception){
        printf("[-] Error in getNextASNBlob: %s\n", exception.reason.UTF8String);
        @throw exception;
    }
}
NSData* carveAsnBlob(ASN1_Obj* blob){
    uint rest_length = 0; //final length of the data
    uint length_bytes = 0;
    uint total_length = 0;
    @try{
        if( ((Byte*)blob.data.bytes)[1] > 0x7F ){
            //this means we need to look at the next sequence of bytes to get full length
            length_bytes = ((Byte*)blob.data.bytes)[1] & 0x7F;
            for(int i = 0; i < length_bytes; i++){
                rest_length <<= 8;
                rest_length |= ((Byte*)blob.data.bytes)[2 + i];
            }
            total_length = rest_length + 2 + length_bytes; //include the type byte and size bytes, this is _total_ length
        }else{
            length_bytes = 1;
            rest_length = ((Byte*)blob.data.bytes)[1] & 0xFF;
            total_length =  rest_length + 2; //include type byte and size byte, this is _total_ length
        }
        //printf("New blob length: %d\nBlob length: %d\n", new_blob.length, blob.length);
        if(total_length > blob.data.length){
            printf("[-] Error: trying to move outside of blob range in carveAsnBlob\n");
            @throw [[NSException alloc] initWithName:@"Future out of bounds" reason:@"Future out of bounds" userInfo:NULL];
        }
        NSData* data = [[NSData alloc] initWithData:[blob.data subdataWithRange:NSMakeRange(0, total_length)]];
        return data;
    }@catch(NSException* exception){
        printf("[-] Error in carveAsnBlob: %s\n", exception.reason.UTF8String);
        @throw exception;
    }
}
ASN1_Obj* carveAsnBlobObject(ASN1_Obj* blob){
    uint rest_length = 0; //final length of the data
    uint length_bytes = 0;
    uint total_length = 0;
    @try{
        if( ((Byte*)blob.data.bytes)[1] > 0x7F ){
            //this means we need to look at the next sequence of bytes to get full length
            length_bytes = ((Byte*)blob.data.bytes)[1] & 0x7F;
            for(int i = 0; i < length_bytes; i++){
                rest_length <<= 8;
                rest_length |= ((Byte*)blob.data.bytes)[2 + i];
            }
            total_length = rest_length + 2 + length_bytes; //include the type byte and size bytes, this is _total_ length
        }else{
            length_bytes = 1;
            rest_length = ((Byte*)blob.data.bytes)[1] & 0xFF;
            total_length =  rest_length + 2; //include type byte and size byte, this is _total_ length
        }
        //printf("New blob length: %d\nBlob length: %d\n", new_blob.length, blob.length);
        if(total_length > blob.data.length){
            printf("[-] Error: trying to move outside of blob range in carveAsnBlobObject while getting sub object\n");
            @throw [[NSException alloc] initWithName:@"Future out of bounds" reason:@"Future out of bounds" userInfo:NULL];
        }
        NSData* data = [[NSData alloc] initWithData:[blob.data subdataWithRange:NSMakeRange(0, total_length)]];
        ASN1_Obj* result = [[ASN1_Obj alloc] initWithType:((Byte*)data.bytes)[0] Length:data.length Data:data];
        result = getNextAsnBlob(result); //gets the length to be total length and moves data forward to the actual content
        // now move the blob object forward
        blob.length = blob.length - result.length;
        if(result.length > blob.data.length){
            printf("[-] Error: trying to move outside of blob range in carveAsnBlobObject while moving base forward\n");
            @throw [[NSException alloc] initWithName:@"Future out of bounds" reason:@"Future out of bounds" userInfo:NULL];
        }
        blob.data = [[NSData alloc] initWithData:[blob.data subdataWithRange:NSMakeRange(result.length, blob.data.length - result.length)]];
        return result;
    }@catch(NSException* exception){
        printf("[-] Error in carveAsnBlobObject: %s\n", exception.reason.UTF8String);
        @throw exception;
    }
}
int getAsnIntegerBlob(ASN1_Obj* blob){
    int value = 0;
    @try{
        //Blob will have data of : 0x02 [NumOfBytes] [value]
        for(int i = 0; i < blob.data.length; i++){
            value <<= 8;
            value |= ((Byte*)blob.data.bytes)[i];
        }
        return value;
    }@catch(NSException* exception){
        printf("[-] Error in getAsnIntegerBlob: %s\n", exception.reason.UTF8String);
        @throw exception;
    }
}
NSString* getAsnGenericStringBlob(ASN1_Obj* blob){
    //given a blob pointing to a generic string, return the string
    @try{
        return [[NSString alloc] initWithBytes:(Byte*)blob.data.bytes length:blob.data.length encoding:NSUTF8StringEncoding];
    }@catch(NSException* exception){
        printf("[-] Error in getAsnGenericStringBlob: %s\n", exception.reason.UTF8String);
        @throw exception;
    }
}
NSData* getAsnOctetStringBlob(ASN1_Obj* blob){
    //return an NSData object of the blob's contents
    @try{
        return [[NSData alloc] initWithData:blob.data];
    }@catch(NSException* exception){
        printf("[-] Error in getAsnOctetStringBlob: %s\n", exception.reason.UTF8String);
        @throw exception;
    }
}
NSData* getAsnLengthBytes(NSData* blob){
    // blob just has the data field set to the bytes. the rest needs to be created
    // return NSData object that contains just the length bytes and the number of those bytes
    Byte* lengthBytes;
    Byte i = 1;
    @try{
        if(blob.bytes == NULL){
            lengthBytes = malloc(1);
            lengthBytes[0] = 0x00;
            NSData* newBlob = [[NSData alloc] initWithBytes:lengthBytes length:i];
            free(lengthBytes);
            return newBlob;
        }
        if( blob.length > 0x7F){
            while(blob.length >> (i * 8) > 0){
                i++;
            }
            // now i should have the number of bytes required to hold the length
            lengthBytes = malloc(i + 1); // bytes and 0x8*
            lengthBytes[0] = 0x80 | i;
            for(int j = 0; j < i; j++){
                lengthBytes[i -j] = (blob.length >> (j * 8)) & 0xFF;
            }
            i++; //make this a final accurate representation of the total number of bytes to represent teh length in ASN1
        }else{
            // simply return the length as a single byte
            lengthBytes = malloc(1);
            *lengthBytes = blob.length & 0xFF;
        }
        NSData* newBlob = [[NSData alloc] initWithBytes:lengthBytes length:i];
        free(lengthBytes);
        return newBlob;
    }@catch(NSException* exception){
        printf("[-] Error in getAsnLengthBytes: %s\n", exception.reason.UTF8String);
        @throw exception;
    }
}
NSData* minimizeAsnInteger(int value){
    //given an integer value, turn it into network byte ordering
    @try{
        Byte* i = malloc(4);
        uint32_t network = htonl(value);
        memcpy(i, &network, 4);
        NSData* result = [[NSData alloc] initWithBytes: i length:4];
        return result;
    }@catch(NSException* exception){
        printf("[-] Error in minimizeAsnInteger: %s\n", exception.reason.UTF8String);
        @throw exception;
    }
}
NSData* createAsnBitString(int value){
    //format is 0x03 [length bytes] [number of bits in last octet not used] [value]
    //given an integer, return the appropriate ASN BitString value
    @try{
        Byte* ByteValue= malloc(5);
        ByteValue[0] = 0x00;
        NSData* reversed = minimizeAsnInteger(value);
        memcpy(ByteValue + 1, reversed.bytes, 4);
        NSData* result = [[NSData alloc] initWithBytes:ByteValue length:5];
        return result;
    }@catch(NSException* exception){
        printf("[-] Error in createAsnBitString: %s\n", exception.reason.UTF8String);
        @throw exception;
    }
}
int getAsnBitString(ASN1_Obj* obj){
    //get the value from a bitstring
    //format is 0x03 [length byte] [number of bits in last octet not used] [value]
    @try{
        Byte* val = (Byte*)obj.data.bytes + 1; // move past the leading zero
        int network = *((int*)val);
        int host = ntohl(network);
        //printf("Got bitstring val: %d\n", host);
        return host;
    }@catch(NSException* exception){
        printf("[-] Error in getAsnBitString: %s\n", exception.reason.UTF8String);
        @throw exception;
    }
}
ASN1_Obj* collapseAsnBasicType(ASN1_Obj* baseBlob){
    // baseBlob has type
    // baseBlob has final value in data, nothing else set though
    // returns ASN1_Obj that has type set, length set, and the _entire_ thing in data (type, size bytes, value)
    ASN1_Obj* final_blob = [ASN1_Obj alloc];
    @try{
        final_blob.type = baseBlob.type;
        //printf("collapsing type: %02X\n", final_blob.type);
        NSData* lengthBytes = getAsnLengthBytes(baseBlob.data);
        Byte* type = malloc(1);
        type[0] = baseBlob.type;
        NSMutableData* collapsedData = [[NSMutableData alloc] initWithBytes:type length:1];
        [collapsedData appendData:lengthBytes];
        [collapsedData appendData:baseBlob.data];
        free(type);
        final_blob.data = collapsedData;
        final_blob.length = collapsedData.length;
        return final_blob;
    }@catch(NSException* exception){
        printf("[-] Error in collapseAsnBasicType: %s\n", exception.reason.UTF8String);
        @throw exception;
    }
}
ASN1_Obj* createCollapsedAsnBasicType(Byte type, NSData* data){
    // length field doesn't matter because the collapseAsnBasicType doesn't look at it, just looks at the length of the bytes
    ASN1_Obj* temp = [[ASN1_Obj alloc] initWithType:type Length:0 Data:data];
    return collapseAsnBasicType(temp);
}
NSData* appendAsnObj(ASN1_Obj* first, ASN1_Obj* second){
    //append the data of the two ASN1_Obj objects and return it in an NSData object
    @try{
        NSMutableData * result = [[NSMutableData alloc] initWithData:first.data];
        [result appendData:second.data];
        return result;
    }@catch(NSException* exception){
        printf("[-] Error in createCollapsedAsnBasicType: %s\n", exception.reason.UTF8String);
        @throw exception;
    }
}
ASN1_Obj* collapseAsnSequence(NSArray<ASN1_Obj*> *sequence){
    //given an array of ASN1_blobs where:
    //  each blob in sequence is already the most compressed of all of its subparts
    if(sequence == nil){
        return [ASN1_Obj alloc];
    }
    ASN1_Obj* collapsed = [ASN1_Obj alloc];
    @try{
        NSMutableData* collapsing = [NSMutableData alloc];
        for(int i = 0; i < [sequence count]; i++){
            //for each element, need to make an encapsulating 0xA* wrapper, then broader 0x30 wrapper around all of it
            ASN1_Obj* temp = [ASN1_Obj alloc];
            temp.type = 0xA0 | i;
            ASN1_Obj* data = [sequence objectAtIndex:i];
            if(data.data != nil){
                temp.data = [sequence objectAtIndex:i].data;
                ASN1_Obj* aStar = collapseAsnBasicType(temp);
                [collapsing appendData:aStar.data];
            }else if(data.data == NULL && data.length == 0x00 && data.type == 0x30){
                //this is a special case of creating an odd empty sequence
                Byte emptyBytes[] = {0x30, 0x00};
                NSData* emptySeq = [[NSData alloc] initWithBytes:emptyBytes length:2];
                [collapsing appendData:emptySeq];
            }
            
        }
        collapsed.type = 0x30;
        collapsed.data = collapsing;
        return collapseAsnBasicType(collapsed);
    }@catch(NSException* exception){
        printf("[-] Error in collapseAsnSequence: %s\n", exception.reason.UTF8String);
        @throw exception;
    }
}
bool isContainerObject(Byte type){
    @try{
        Byte containers[] = {0x30};
        for(int i = 0; i < 1; i++){
            if(type == containers[i]){
                return true;
            }
        }
        // 0xA0-AF are elements in a sequence and just contain the element within them
        if( (type & 0xF0) == 0xA0){
            return true;
        }
        // 0x60-F different kinds of applications as well
        if( (type & 0xF0) == 0x60){
            return true;
        }
        // 0x70-F different kinds of applications as well
        if( (type & 0xF0) == 0x70){
            return true;
        }
        return false;
    }@catch(NSException* exception){
        printf("[-] Error in isContainerObject: %s\n", exception.reason.UTF8String);
        @throw exception;
    }
}
