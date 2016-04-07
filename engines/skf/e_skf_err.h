#ifndef HEADER_SKF_ERR_H
#define HEADER_SKF_ERR_H


#ifdef  __cplusplus
extern "C" {
#endif


static void ERR_load_SKF_strings(void);
static void ERR_unload_SKF_strings(void);
static void ERR_SKF_error(int function, int reason, char *file, int line);
# define SKFerr(f,r) ERR_SKF_error((f),(r),__FILE__,__LINE__)



/* Function codes. */
#define SKF_F_SKF_RAND                                 100


/* Reason codes. */
#define SKF_R_OK					110
#define SKF_R_FAIL					101
#define SKF_R_UNKNOWNERR				102
#define SKF_R_NOTSUPPORTYETERR				103
#define SKF_R_FILEERR					104
#define SKF_R_INVALIDHANDLEERR				105
#define SKF_R_INVALIDPARAMERR				106
#define SKF_R_READFILEERR				107
#define SKF_R_WRITEFILEERR				108
#define SKF_R_NAMELENERR				109
#define SKF_R_KEYUSAGEERR				110
#define SKF_R_MODULUSLENERR				111
#define SKF_R_NOTINITIALIZEERR				112
#define SKF_R_OBJERR					113
#define SKF_R_MEMORYERR					114
#define SKF_R_TIMEOUTERR				115
#define SKF_R_INDATALENERR				116
#define SKF_R_INDATAERR					117
#define SKF_R_GENRANDERR				118
#define SKF_R_HASHOBJERR				119
#define SKF_R_HASHERR					120
#define SKF_R_GENRSAKEYERR				121
#define SKF_R_RSAMODULUSLENERR				122
#define SKF_R_CSPIMPRTPUBKEYERR				123
#define SKF_R_RSAENCERR					124
#define SKF_R_RSADECERR					125
#define SKF_R_HASHNOTEQUALERR				126
#define SKF_R_KEYNOTFOUNTERR				127
#define SKF_R_CERTNOTFOUNTERR				128
#define SKF_R_NOTEXPORTERR				129
#define SKF_R_DECRYPTPADERR				130
#define SKF_R_MACLENERR					131
#define SKF_R_BUFFER_TOO_SMALL				132
#define SKF_R_KEYINFOTYPEERR				133
#define SKF_R_NOT_EVENTERR				134
#define SKF_R_DEVICE_REMOVED				135
#define SKF_R_PIN_INCORRECT				136
#define SKF_R_PIN_LOCKED				137
#define SKF_R_PIN_INVALID				138
#define SKF_R_PIN_LEN_RANGE				139
#define SKF_R_USER_ALREADY_LOGGED_IN			140
#define SKF_R_USER_PIN_NOT_INITIALIZED			141
#define SKF_R_USER_TYPE_INVALID				142
#define SKF_R_APPLICATION_NAME_INVALID			143
#define SKF_R_APPLICATION_EXISTS			144
#define SKF_R_USER_NOT_LOGGED_IN			145
#define SKF_R_APPLICATION_NOT_EXISTS			146
#define SKF_R_FILE_ALREADY_EXIST			147
#define SKF_R_NO_ROOM					148
#define SKF_R_FILE_NOT_EXIST				149


#ifdef  __cplusplus
}
#endif
#endif
