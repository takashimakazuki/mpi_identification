#ifndef LOGGER_H_
#define LOGGER_H_

#define LOG_FILE_SIZE_MAX_COL_MAX 7   // ログファイルサイズカラム数
#define LOG_FILE_SIZE_MAX_MIN 1       // ログファイルサイズの最大サイズKB(1)
#define LOG_FILE_SIZE_MAX_MAX 2097151 // ログファイルサイズの最大サイズKB個数(2097151)7FFFFC00

#define LOG_FILE_DEF_PATH "./mpi_log"      // ログファイルのデフォルトパス
#define LOG_FILE_DEF_SIZE_MAX 10 * 1024 // ログファイルのデフォルト最大サイズ
#define LOG_FILE_DEF_NUM_MAX 99     // ログファイルのデフォルト最大世代数
#define LOG_TYPE_APL 0
#define LOG_DATETIME_FORMAT "%04d-%02d-%02dT%02d:%02d:%02d.%06lu"

typedef struct _INI_VALUE_LOG
{
    char logFilePathName[1024]; // ログファイルのパス名(フルパス)
    int logFileSizeMax;         // ログファイルの最大サイズ(KB)
    int logFileNumMax;          // ログファイルの最大世代数(1-99)
} INI_VALUE_LOG;

// ログファイルNo 0:ファイル未確定 1以上:ファイル名確定中
extern int gLogCurNo;

extern INI_VALUE_LOG gIniValLog;

void getCurrentLogFileNo(int fileType);
void putLog(char *format, ...);
void flush_mpilog_buf();

#endif /* LOGGER_H_ */