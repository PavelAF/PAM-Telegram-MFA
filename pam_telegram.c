#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <libconfig.h>
#include <stdbool.h>

#define PAM_SM_AUTH
#ifndef FALSE
#define FALSE   (0)
#endif

//#include <security/pam_misc.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <pwd.h>

/* json-c (https://github.com/json-c/json-c) */
#include <json-c/json.h>

/* libcurl (http://curl.haxx.se/libcurl/c) */
#include <curl/curl.h>


struct MemoryStruct {
  char *memory;
  size_t size;
};


int telegramGetResponse(char* baseurl, int chatId, char** data);
int telegramSend2fa(char* baseurl, int chatId);
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
                retval = conv->conv( nargs, (const struct pam_message **) message, response, conv->appdata_ptr ) ;
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

    struct pam_message msg[1],*pmsg[1];
    struct pam_response *resp;

    char apiurl[] = "https://api.telegram.org/bot";

    int chatId, timeout, force, retval;
    char* configFile;

    if (argc == 1){
        configFile = (char*) malloc(strlen(argv[0])+1);
        strcpy(configFile,argv[0]);
    }else{
        configFile = (char*) malloc(strlen("/etc/pam_telegram.cfg")+1);
        strcpy(configFile,"/etc/pam_telegram.cfg");
    }

        retval = pam_get_user(pamh, &pUsername, "Username: ");

    pwd = getpwnam(pUsername);

    if (!pwd) {
        logging("Error", "impossible looking up user information for: %s", pUsername);
        converseInfo(pamh,"HAM: host verification error");
                return 1;
        }

    sprintf(str_uid, "%u", pwd->pw_uid);
    strcpy(uid_str_uid, "uid-");
    strcat(uid_str_uid, str_uid);

    config_init(&cfg);

    if (!config_read_file(&cfg, configFile)) {
        logging("Error","Configuration file \"%s\" not found or syntax error", configFile);
        converseInfo(pamh,"HAM: host verification error");
        config_destroy(&cfg);
        return 1;
    }

    root = config_root_setting(&cfg);

    /* Get time out from config file*/
    setting = config_setting_get_member(root, "timeout");
    if (!setting) {
        timeout = 30;
    } else {
        timeout = config_setting_get_int(setting);
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
        return(force == FALSE ? 0:1 );
    } else {
        logging("Info","User \"%s\"(%s) FOUND in config file", pUsername, uid_str_uid);
    }

    chatId = config_setting_get_int(setting);

    /* Get apikey from config file*/
    setting = config_setting_get_member(root, "apikey");
    if (!setting) {
        converseInfo(pamh,"HAM: host verification error");
        logging("Error","Api key not found");
        return 1;
    }

    /* Build base url */
    pBaseurl = (char*)malloc(strlen(apiurl)+strlen(config_setting_get_string(setting))+1);
    strcpy(pBaseurl, apiurl);
    strcat(pBaseurl, config_setting_get_string(setting));

    if (telegramSend2fa(pBaseurl, chatId)) {    /* 2fa message send? */
        int i;

        converseInfo(pamh,"HAM message send... Please respond within %i seconds", timeout);
        delay(1000);
        for (i=0; i<timeout; i++) {
            char *response;

            if (telegramGetResponse(pBaseurl,chatId,&response)) {
                if (response != NULL) {
                    if (strcmp(response, "\"Approve\"") == 0) {
                        converseInfo(pamh,"HAM: OK");
                        free(response);
                        return PAM_SUCCESS;   /* Get an approve message from telegram > return 0 = OK */
                    } else if (strcmp(response, "\"Deny\"") == 0) {
                        free(response);
                        free(pBaseurl);
                        converseInfo(pamh,"HAM: host verification error");
                        logging("Alert","User denied");
                        return PAM_OPEN_ERR;
                    }
                }
            } else {
                free(response);
                converseInfo(pamh,"HAM: host verification error");
                logging("Error","Error while retrieving response");
                break;
            }
            delay(700);
        }
        converseInfo(pamh,"HAM: host verification error");
        logging("Error","MFA: No response");
    } else {
        converseInfo(pamh,"MFA: Error: Cannot send the 2fa message. Check the logs for details");
    }

    free(pBaseurl);

    return PAM_OPEN_ERR;
}

int telegramGetResponse(char* pBaseurl, int chatId, char** data)
{
    //std::string* pResponse = new std::string;
    //char* pResponse;

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

    retval = curlSend(pUrl, (char*)"", method,&response);
    free(pUrl);

    if (retval) {

        json_object* jResponseOk;
        json_object* jResponse = json_tokener_parse(response.memory);
        json_object_object_get_ex(jResponse, "ok", &jResponseOk);

        if (json_object_get_boolean(jResponseOk)) {

            json_object *jResponseResult, *jResponseResults, *jResponseResultMessage, *jResponseResultMessageText, *jResponseResultMessageDate, *jResponseResultMessageChat, *jResponseResultMessageChatId;
            int exists, i;

            /* Get result */
            exists = json_object_object_get_ex( jResponse, "result", &jResponseResults );
            if ( FALSE == exists ) {
                logging( "Error", "Function: telegramGetResponse: \"result\" not found in JSON: %s", response.memory );
                return 0;
            }

            for (i = json_object_array_length(jResponseResults)-1; i >= 0 ; i--) {

                jResponseResult = json_object_array_get_idx( jResponseResults, i );

                /* Get message */
                exists = json_object_object_get_ex( jResponseResult, "message", &jResponseResultMessage );
                if (FALSE == exists) {
                    logging( "Error", "Function: telegramGetResponse: \"result\"->\"message\" not found in JSON: %s", response.memory );
                    return 0;
                }

                /* Get text */
                exists = json_object_object_get_ex( jResponseResultMessage, "text", &jResponseResultMessageText );
                if (FALSE == exists) {
                    logging( "Error", "Function: telegramGetResponse: \"result\"->\"message\"->\"text\" not found in JSON: %s", response.memory );
                    return 0;
                }

                /* Get date */
                exists = json_object_object_get_ex( jResponseResultMessage, "date", &jResponseResultMessageDate );
                if (FALSE == exists) {
                    logging( "Error", "Function: telegramGetResponse: \"result\"->\"message\"->\"date\" not found in JSON: %s", response.memory );
                    return 0;
                }

                /* Get chat */
                exists = json_object_object_get_ex( jResponseResultMessage, "chat", &jResponseResultMessageChat );
                if (FALSE == exists) {
                    logging( "Error", "Function: telegramGetResponse: \"result\"->\"message\"->\"chat\" not found in JSON: %s", response.memory );
                    return 0;
                }

                /* Get chat id */
                exists = json_object_object_get_ex( jResponseResultMessageChat, "id", &jResponseResultMessageChatId );
                if (FALSE == exists) {
                    logging( "Error", "Function: telegramGetResponse: \"result\"->\"message\"->\"chat\"->\"id\" not found in JSON: %s", response.memory );
                    return 0;
                }

                /* Only messages not older then two seconds ago */
                if ((time(NULL) - json_object_get_int(jResponseResultMessageDate)) < 2) {
                    if (json_object_get_int(jResponseResultMessageChatId) == chatId) {
                        *data = (char*)malloc( strlen( json_object_to_json_string(jResponseResultMessageText) ) + 1 );
                        strcpy( *data, json_object_to_json_string(jResponseResultMessageText) );
                        return 1;    /* No error. data is filled with the message */
                    }
                }
            }
            *data = NULL;
            return 1;   /* No error. data is NULL */
        }
    }

    /* Error */
    return 0;
}

int telegramSend2fa(char* pBaseurl, int chatId)
{

    struct MemoryStruct response;

    int retval;
    char method[] = "POST";
    char data[] = "{\"text\":\"Approve sign-in?\", \"reply_markup\": {\"keyboard\": [[\"Approve\",\"Deny\"]],\"one_time_keyboard\":true, \"resize_keyboard\":true}}";

    response.memory = (char*)malloc(1);
    response.size = 0;

    /* Build url */
    char* pUrl;
    pUrl = (char*)malloc( strlen(pBaseurl) + strlen("/sendMessage") + 1 );
    strcpy( pUrl, pBaseurl );
    strcat( pUrl, "/sendMessage" );

    json_object* jData = json_tokener_parse( data );
    json_object_object_add( jData, "chat_id", json_object_new_int(chatId) );

    logging("Debug","Function: telegramSend2fa: URL %s: %s", method, pUrl);
    logging("Debug","Function: telegramSend2fa: JSON out: %s", json_object_to_json_string(jData));

    retval = curlSend( pUrl, (char*)json_object_to_json_string(jData), method, &response );
    free(pUrl);

    if (retval) {
        json_object* jResponseOk;
        json_object* jResponse = json_tokener_parse( response.memory );
        json_object_object_get_ex( jResponse, "ok", &jResponseOk );

        if (json_object_get_boolean(jResponseOk)) {
            return 1; /* OK */
        } else {
            logging("Error","Function: telegramSend2fa: JSON \"ok\" is false: %s", response.memory);
        }
    }

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
}
