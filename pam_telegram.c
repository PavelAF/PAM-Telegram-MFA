#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <libconfig.h>
#include <stdbool.h>

#include <limits.h>
#include <unistd.h>

#ifndef FALSE
#define FALSE   (0)
#endif

#define PAM_SM_AUTH

//#include <security/pam_misc.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <pwd.h>

#include <syslog.h>

/* json-c (https://github.com/json-c/json-c) */
#include <json-c/json.h>

/* libcurl (http://curl.haxx.se/libcurl/c) */
#include <curl/curl.h>


struct MemoryStruct {
  char *memory;
  size_t size;
};


int telegramGetResponseCallBack(char* pBaseurl, int chatId, int messageId, char** data);
int telegramSend2faRequest(char* pBaseurl, int chatId, int *messageId, char* text);
int telegramSend2faResult(char* pBaseurl, int chatId, int messageId, char* text);
int telegramSendjData(char* pBaseurl, char* apimethod, json_object** jData);
int curlSend(char* url, char* data, char* method, struct MemoryStruct* response_string);
void logging(const char* logtype,const char* format, ...);

char const* pLogfilePath = "/var/log/pam_telegram.log";

static size_t write_data(void *contents, size_t size, size_t nmemb, struct MemoryStruct* mem)
{
    size_t realsize = size * nmemb;

    mem->memory = (char*)realloc(mem->memory, mem->size + realsize + 1);
    if(mem->memory == NULL) {
        /* out of memory! */ 
        puts("MFA: not enough memory (realloc returned NULL)");
        
        return 0;
    }

    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}


void delay(int milli_seconds) 
{ 
    clock_t start_time = clock(); 
    while (clock() < start_time + ((float)(milli_seconds/1000.0)*CLOCKS_PER_SEC)); 
}

/* this function is ripped from pam_unix/support.c, it lets us do IO via PAM */
int converse( pam_handle_t *pamh, int nargs, struct pam_message **message, struct pam_response **response )
{
	int retval ;
	struct pam_conv *conv ;

	retval = pam_get_item( pamh, PAM_CONV, (const void **) &conv ) ; 
	if( retval==PAM_SUCCESS ) {
		retval = conv->conv( nargs, (const struct pam_message **) message, response, conv->appdata_ptr );
	}

	return retval ;
}

void converseInfo(pam_handle_t *pamh, const char* pMessage, ...)
{
    va_list args;
    struct pam_message msg,*pmsg[1];
    struct pam_response *resp;
    char pBuf[200];

    va_start (args, pMessage);
    vsprintf (pBuf, pMessage, args);
    va_end (args);

    pmsg[0] = &msg;
    msg.msg_style = PAM_TEXT_INFO;
	msg.msg = pBuf;    
	
    converse(pamh, 1 , pmsg, &resp);

}


/* expected hook */
int pam_sm_setcred( pam_handle_t *pamh, int flags, int argc, const char **argv ) 
{
	return PAM_SUCCESS;
}


/* expected hook, this is where custom stuff happens */
int pam_sm_authenticate( pam_handle_t *pamh, int flags,int argc, const char **argv )
{
    config_t cfg;
    config_setting_t *root, *setting;
    const char* pUsername;
    const struct passwd *pwd;
    char str_uid[sizeof(unsigned int)+1];
    char uid_str_uid[4+sizeof(unsigned int)+1];
    char* pBaseurl;
    const char* pRHost;
    const char* pService;
    char* tg_req_text;

    char hostname[HOST_NAME_MAX + 1];

    hostname[HOST_NAME_MAX] = 0;

    if (gethostname(hostname, sizeof(hostname) - 1) != 0)
    {
        logging("Error","Can not get machine Hostname");
        converseInfo(pamh,"HAM: host verification error");
        return PAM_SERVICE_ERR;
    }

    char apiurl[] = "https://api.telegram.org/bot";

    int chatId, messageId, timeout, force, retval;
    char* configFile;

	retval = pam_get_user(pamh, &pUsername, "Username: ");
	if (retval != PAM_SUCCESS) {
        logging("Error","Can not get Username");
        converseInfo(pamh,"HAM: host verification error");
        return PAM_USER_UNKNOWN;
	}
    
    pwd = getpwnam(pUsername);
    if (!pwd) {
        logging("Error", "impossible looking up user information for: %s", pUsername);
        converseInfo(pamh,"HAM: host verification error");
		return PAM_USER_UNKNOWN;
	}

    retval = pam_get_item(pamh, PAM_RHOST, (const void **)&pRHost);
	if (retval != PAM_SUCCESS) {
        logging("Error","Can not get RHost PAM_ITEM");
        converseInfo(pamh,"HAM: host verification error");
        return PAM_AUTHINFO_UNAVAIL;
	}
    
    retval = pam_get_item(pamh, PAM_SERVICE, (const void **)&pService);
	if (retval != PAM_SUCCESS) {
        logging("Error","Can not get RHost PAM_ITEM");
        converseInfo(pamh,"HAM: host verification error");
        return PAM_AUTHINFO_UNAVAIL;
	}

    
    /*logging("Debug","RHost=\"%s\" Service=\"%s\"", pRHost,pService);*/
    logging("Debug","RHost=\"%s\" Service=\"%s\" Hostname=\"%s\"", pRHost,pService,hostname);

    sprintf(str_uid, "%u", pwd->pw_uid);
    strcpy(uid_str_uid, "uid-");
    strcat(uid_str_uid, str_uid);

    if (argc == 1){
        configFile = (char*) malloc(strlen(argv[0])+1);
        strcpy(configFile,argv[0]);
    }else{
        configFile = (char*) malloc(strlen("/etc/pam_telegram.cfg")+1);
        strcpy(configFile,"/etc/pam_telegram.cfg");
    }
    
    config_init(&cfg);

    if (!config_read_file(&cfg, configFile)) {
        logging("Error","Configuration file \"%s\" not found or syntax error", configFile);
        converseInfo(pamh,"HAM: host verification error");
        config_destroy(&cfg);
        free(configFile);
        return PAM_OPEN_ERR;
    }
    free(configFile);

    root = config_root_setting(&cfg);

    /* Get time out from config file*/
    setting = config_setting_get_member(root, "timeout");
    if (!setting) {
        timeout = 15;
    } else {
        timeout = config_setting_get_int(setting);
    }

    /* Get custom hostname for message display */
    setting = config_setting_get_member(root, "hostname");
    if (setting && strlen(config_setting_get_string(setting))) {
        strcpy(hostname,config_setting_get_string(setting));
    }

    /* Get force option from config file*/
    setting = config_setting_get_member(root, "force");
    if (!setting) {
        force = FALSE;
    } else {
        force = config_setting_get_bool(setting);
    }

    
    /* Get chat id from config file*/
    setting = config_setting_get_member(root, uid_str_uid);
    if (!setting) {
        /* User not found in config file. Return true or false based on force option */
        logging("Notice","User \"%s\"(%s) NOT fount in config file", pUsername, uid_str_uid);
        converseInfo(pamh,"HAM: host verification error");
        return(force == FALSE ? PAM_IGNORE:PAM_PERM_DENIED );
    } else {
        logging("Info","User \"%s\"(%s) FOUND in config file", pUsername, uid_str_uid);
    }

    chatId = config_setting_get_int(setting);

    /* Get apikey from config file*/
    setting = config_setting_get_member(root, "apikey");
    if (!setting) {
        converseInfo(pamh,"HAM: host verification error");
        logging("Error","Api key not found");
        return PAM_NO_MODULE_DATA;
    }

    /* Build base url */
    pBaseurl = (char*)malloc(strlen(apiurl)+strlen(config_setting_get_string(setting))+1);
    strcpy(pBaseurl, apiurl);
    strcat(pBaseurl, config_setting_get_string(setting));

    if(asprintf(&tg_req_text, "\xF0\x9F\x94\xA5<b>%s</b>: attempt <b>AUTH\nService: %s\nUser: %s\nR-host: %s\nAllow authentication?</b>", hostname, pService, pUsername, pRHost) < 0) {
        free(pBaseurl);
        return PAM_SERVICE_ERR;
    }
    
    /*logging("Debug","tg-message=\"%s\"", tg_req_text);*/

    if (telegramSend2faRequest(pBaseurl, chatId, &messageId, tg_req_text)) {    /* 2fa message send? */
        int i;
        
        free(tg_req_text);
        converseInfo(pamh,"HAM send... waiting for a response");
        delay(1000);
        for (i=0; i<timeout; i++) {

            delay(1000);
            
            char *response;
            
            if (telegramGetResponseCallBack(pBaseurl, chatId, messageId, &response)) {
                if (response != NULL) {
                    if (strcmp(response, "\"accept\"") == 0) {
                        if(asprintf(&tg_req_text, "\xE2\x9C\x85 <b>%s</b>: auth <b>ACCEPT\nService: %s\nUser: %s\nR-host: %s</b>", hostname, pService, pUsername, pRHost) < 0) { return PAM_SERVICE_ERR; }
                        telegramSend2faResult(pBaseurl, chatId, messageId, tg_req_text);
                        free(tg_req_text);

                        converseInfo(pamh,"HAM: OK");
                        pam_syslog(pamh, LOG_NOTICE, "auth_telegram=[ SUCCESS ] for %s",pUsername);
                        free(response);
                        free(pBaseurl);
                        return PAM_SUCCESS;   /* Get an approve message from telegram > return 0 = OK */
                    } else if (strcmp(response, "\"deny\"") == 0) {
                        if(asprintf(&tg_req_text, "\xF0\x9F\x9A\xA8<b>%s</b>: auth <b>REJECT\nService: %s\nUser: %s\nR-host: %s\n</b>", hostname, pService, pUsername, pRHost) < 0) { return PAM_SERVICE_ERR; }
                        telegramSend2faResult(pBaseurl, chatId, messageId, tg_req_text);
                        free(tg_req_text);

                        converseInfo(pamh,"HAM: host verification error");
                        logging("Alert","User denied");
                        pam_syslog(pamh, LOG_WARNING, "auth_telegram=[ DENY ] for %s",pUsername);
                        free(response);
                        free(pBaseurl);
                        return PAM_PERM_DENIED;
                    } 
                }
            } else {
                free(response);
                converseInfo(pamh,"HAM: host verification error");
                logging("Error","Error while retrieving response");
                free(response); free(pBaseurl);
                break;
            }
        }
        if(asprintf(&tg_req_text, "\xF0\x9F\x9A\xAB <b>%s</b>: auth <b>TIMEOUT\nService: %s\nUser: %s\nR-host: %s</b>", hostname, pService, pUsername, pRHost) < 0) { return PAM_SERVICE_ERR; }
        telegramSend2faResult(pBaseurl, chatId, messageId, tg_req_text);
        free(tg_req_text);
        converseInfo(pamh,"HAM: host verification error");
        logging("Error","MFA: No response");
        pam_syslog(pamh, LOG_ERR, "auth_telegram=[DENY-TIMEOUT] for %s",pUsername);
        free(pBaseurl);
        return PAM_CRED_UNAVAIL;
    } else {
        free(tg_req_text);
        converseInfo(pamh,"HAM: host verification error");
        logging("Error","MFA: Error: Cannot send the 2fa message. Check the logs for details");
    }

    free(pBaseurl);
    
    pam_syslog(pamh, LOG_ERR, "auth_telegram=[DENY-ERROR] for %s",pUsername);
    return PAM_AUTH_ERR;
}

int telegramGetResponseCallBack(char* pBaseurl, int chatId, int messageId, char** data)
{
    struct MemoryStruct response;

    response.memory = (char*)malloc(1);  /* will be grown as needed by the realloc above */ 
    response.size = 0;    /* no data at this point */ 

    char method[] = "GET";
    int retval;

    /* Build url */
    char* pUrl;
    pUrl = (char*)malloc(strlen(pBaseurl)+strlen("/getUpdates")+1);
    strcpy(pUrl, pBaseurl);
    strcat(pUrl, "/getUpdates");
    
    json_object* jData = json_tokener_parse( "{ \"offset\": -15, \"limit\":15 }" );


    logging("Debug","Function: telegramSend2fa: URL %s: %s", method, pUrl);

    retval = curlSend(pUrl, (char*)json_object_to_json_string(jData), method,&response);

    free(pUrl);


    if (retval) {

        json_object* jResponseOk;
        json_object* jResponse = json_tokener_parse(response.memory);
        json_object_object_get_ex(jResponse, "ok", &jResponseOk);

        if (json_object_get_boolean(jResponseOk)) {
            
            json_object *jResponseResults, *jResponseResultUpdateId, *jResponseResultCallBack, *jResponseResultMessage, *jResponseResultMessageId, *jResponseResultCData, *jResponseResultMessageDate, *jResponseResultMessageChat, *jResponseResultMessageChatId;
            int exists, i;
            
            /* Get result */
            exists = json_object_object_get_ex( jResponse, "result", &jResponseResults );

            if ( FALSE == exists ) {
                logging( "Error", "Function: telegramGetResponse: \"result\" not found in JSON: %s", json_object_to_json_string(jResponse) );
                return 0;
            }

            logging( "Debug", "Function: telegramGetResponse result: %s", json_object_to_json_string(jResponse) );
            
            for (i = json_object_array_length(jResponseResults)-1; i >= 0 ; i--) {

                json_object *jResponseResult = json_object_array_get_idx( jResponseResults, i );

                exists = json_object_object_get_ex( jResponseResult, "update_id", &jResponseResultUpdateId );
                if (FALSE == exists) {
                    logging( "Error", "Function: telegramGetResponse: \"result\"->\"update_id\" not found in JSON: %s", json_object_to_json_string(jResponseResult) );
                    return 0;
                }

                exists = json_object_object_get_ex( jResponseResult, "callback_query", &jResponseResultCallBack );
                if (FALSE == exists) {
                    logging( "Debug", "Function: telegramGetResponse: \"result\"->\"callback_query\" not found in JSON update_id=%s", json_object_to_json_string(jResponseResultUpdateId) );
                    continue;
                }

                /* Get callback data */
                exists = json_object_object_get_ex( jResponseResultCallBack, "data", &jResponseResultCData );
                if (FALSE == exists) {
                    logging( "Error", "Function: telegramGetResponse: \"result\"->\"callback_query\"->\"data\" not found in JSON: %s", json_object_to_json_string(jResponseResultCallBack) );
                    return 0;
                }

                /* Get message */
                exists = json_object_object_get_ex( jResponseResultCallBack, "message", &jResponseResultMessage );
                if (FALSE == exists) {
                    logging( "Error", "Function: telegramGetResponse: \"result\"->\"callback_query\"->\"message\" not found in JSON: %s", json_object_to_json_string(jResponseResultCallBack) );
                    return 0;
                }

                /* Get messageId */
                exists = json_object_object_get_ex( jResponseResultMessage, "message_id", &jResponseResultMessageId );
                if (FALSE == exists) {
                    logging( "Error", "Function: telegramGetResponse: \"result\"->\"callback_query\"->\"message\"->\"message_id\" not found in JSON: %s", response.memory );
                    return 0;
                }

                /* Get date */
                exists = json_object_object_get_ex( jResponseResultMessage, "date", &jResponseResultMessageDate );
                if (FALSE == exists) {
                    logging( "Error", "Function: telegramGetResponse: \"result\"->\"callback_query\"->\"message\"->\"date\" not found in JSON: %s", response.memory );
                    return 0;
                }
                
                /* Get chat */
                exists = json_object_object_get_ex( jResponseResultMessage, "chat", &jResponseResultMessageChat );
                if (FALSE == exists) {
                    logging( "Error", "Function: telegramGetResponse: \"result\"->\"callback_query\"->\"message\"->\"chat\" not found in JSON: %s", response.memory );
                    return 0;
                }

                /* Get chat id */
                exists = json_object_object_get_ex( jResponseResultMessageChat, "id", &jResponseResultMessageChatId );
                if (FALSE == exists) {
                    logging( "Error", "Function: telegramGetResponse: \"result\"->\"callback_query\"->\"message\"->\"chat\"->\"id\" not found in JSON: %s", response.memory );
                    return 0;
                }
                
                /* Only messages not older then two seconds ago */
                /*if ((time(NULL) - json_object_get_int(jResponseResultMessageDate)) < 2) {*/
                if (json_object_get_int(jResponseResultMessageId) == messageId && json_object_get_int(jResponseResultMessageChatId) == chatId) {
                    *data = (char*)malloc( strlen( json_object_to_json_string(jResponseResultCData) ) + 1 );
                    strcpy( *data, json_object_to_json_string(jResponseResultCData) );
                    logging( "Debug", "Function: telegramGetResponse: result JSON: %s", *data );
                    return 1;    /* No error. data is filled with the message */
                }
            }

            /* logging( "Debug", "Function: telegramGetResponse: \"result\"->\"callback_query\" 0 not found in JSON: %s", response.memory ); */

            *data = NULL;
            return 1;   /* No error. data is NULL */
        }
    }

    /* Error */
    return 0;
}

int telegramSend2faRequest(char* pBaseurl, int chatId, int *messageId, char* text)
{
    int retval;
    json_object* jData = json_tokener_parse( 
            "{\"reply_markup\": { \"inline_keyboard\": [[ { \"text\": \"Accept\", \"callback_data\": \"accept\" },  { \"text\": \"Deny\", \"callback_data\": \"deny\" } ]] } }" );
    json_object_object_add( jData, "chat_id", json_object_new_int(chatId) );
    json_object_object_add( jData, "text", json_object_new_string(text) );
    /*json_object_object_add( jData, "text", json_object_new_string("accept?") );*/
    json_object_object_add( jData, "parse_mode", json_object_new_string("HTML") );
    retval = telegramSendjData(pBaseurl, "/sendMessage", &jData);
    json_object_object_get_ex( jData, "result", &jData );
    json_object_object_get_ex( jData, "message_id", &jData );
    *messageId = json_object_get_int(jData);
    return retval;
}

int telegramSend2faResult(char* pBaseurl, int chatId, int messageId, char* text)
{
    json_object* jData = json_object_new_object();
    json_object_object_add( jData, "chat_id", json_object_new_int(chatId) );
    json_object_object_add( jData, "message_id", json_object_new_int(messageId) );
    json_object_object_add( jData, "text", json_object_new_string(text) );
    json_object_object_add( jData, "parse_mode", json_object_new_string("HTML") );
    return telegramSendjData(pBaseurl, "/editMessageText", &jData);
}

int telegramSendjData(char* pBaseurl, char* apimethod, json_object** jData)
{
    
    struct MemoryStruct response;

    int retval;
    char method[] = "POST";
    
    response.memory = (char*)malloc(1);
    response.size = 0;

    /* Build url */
    char* pUrl;
    pUrl = (char*)malloc( strlen(pBaseurl) + strlen(apimethod) + 1 );
    strcpy( pUrl, pBaseurl );
    strcat( pUrl, apimethod );

    logging("Debug","Function: telegramSend2fa: URL %s: %s", method, apimethod);
    logging("Debug","Function: telegramSend2fa: JSON out: %s", json_object_to_json_string(*jData));

    retval = curlSend( pUrl, (char*)json_object_to_json_string(*jData), method, &response );
    free(pUrl);

    if (retval) {
        json_object* jResponseOk;
        *jData = json_tokener_parse( response.memory );
        json_object_object_get_ex( *jData, "ok", &jResponseOk );

        if (json_object_get_boolean(jResponseOk)) {
            logging("Debug","Function: telegramSend2fa: JSON Result: %s", response.memory);
            free(response.memory);
            return 1; /* OK */
        } else {
            logging("Error","Function: telegramSend2fa: JSON \"ok\" is false: %s", response.memory);
        }
    }
    
    free(response.memory);
    /* Error */
    return 0;
}

int curlSend(char* url, char* pData, char* pMethod, struct MemoryStruct* pResponse)
{
    
    CURL *curl;
    CURLcode res;
    struct curl_slist* pHeaders = NULL;  /* http headers to send with request */

    curl_global_init(CURL_GLOBAL_ALL);
 
    /* Get a curl handle */ 
    curl = curl_easy_init();
    if (curl) {

        /* set content type */
        pHeaders = curl_slist_append(pHeaders, "Accept: application/json");
        pHeaders = curl_slist_append(pHeaders, "Content-Type: application/json");

        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, pMethod);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, pHeaders);
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, pData);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, pResponse);

        /* Perform the request, res will get the return code */ 
        res = curl_easy_perform(curl);

        /* always cleanup */ 
        curl_easy_cleanup(curl);
    } else {
        logging("Error","curl_easy_init() failed");
        return 0;
    }
    
    curl_global_cleanup();
    
    /* Check for errors */ 
    if (res != CURLE_OK) {
        logging("Error","curl_easy_perform() failed: %s",curl_easy_strerror(res));
        return 0;
    }

    return 1;
}

void logging(const char* pLogtype,const char* pFormat, ...) { 
    char* pBuf;
    va_list args;

    time_t rawtime;
    struct tm *info;
    char formattedTime[20];

    //FILE *pLogfile = ;
    FILE *pLogfile = fopen(pLogfilePath, "a");

    if (pLogfile == NULL) { 
        /* Something is wrong   */
        puts("MFA: Error: Cannot access logfile");
        return;
    }

    time( &rawtime );
    info = localtime( &rawtime );
    strftime(formattedTime,20,"%Y-%m-%d %H:%M:%S", info);

    pBuf = (char*)malloc(strlen(formattedTime)+1+strlen(pLogtype)+3+strlen(pFormat)+1);

    sprintf(pBuf, "%s [%s] %s\n", formattedTime, pLogtype, pFormat);

    va_start (args, pFormat);
    vfprintf (pLogfile, pBuf, args);
    va_end (args);
    fclose(pLogfile);
    free(pBuf);
}
