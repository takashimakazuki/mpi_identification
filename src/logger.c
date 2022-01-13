#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <pthread.h>
#include <stdarg.h>
#include <sys/time.h>
#include <time.h>

#include "logger.h"

// #define DEBUG

#define LOG_FILE_SIZE_KB 1024
// ログファイル名
#define LOG_FILE_NAME "mpi_log"
// バッファリングサイズ(bytes)
#define LOG_BUF_SIZE 1000000

// グローバル変数
// ログファイルNo 0:ファイル未確定 1以上:ファイル名確定中
int gLogCurNo;
// INI定義値(LOG)
INI_VALUE_LOG gIniValLog;

// ログファイル排他用ミューテックス
pthread_mutex_t mutexLog = PTHREAD_MUTEX_INITIALIZER;

char mpilog_buf[LOG_BUF_SIZE];

#ifdef DEBUG
clock_t start, end;
double cpu_time_pthread_mutex_lock;
double cpu_time_getDateTime;
double cpu_time_get_filename;
double cpu_time_file_write;
#endif

// TODO: BOFの危険あり．dateTimeLenで出力文字数の制限を行う．
int getDateTime(char *format, int dateTimeLen, char *dateTime)
{
    int ret = 0;
    struct timeval timevalData;
    struct tm timeData;

    ret = gettimeofday(&timevalData, NULL);
    if (ret == -1)
    {
        return -1;
    }

    if (localtime_r(&timevalData.tv_sec, &timeData) == NULL)
    {
        return -1;
    }

    sprintf(dateTime, format,
            timeData.tm_year + 1900,
            timeData.tm_mon + 1,
            timeData.tm_mday,
            timeData.tm_hour,
            timeData.tm_min,
            timeData.tm_sec,
            timevalData.tv_usec);
    return ret;
}

void putLog(char *format, ...)
{
    int ret;             // 戻り値
    char dateTime[48];   // 現在日時
    struct stat stStat;  // ファイル情報の格納領域
    FILE *fp;            // ファイルディスクプリタ
    char fileName[2048]; // ログファイル名
    off_t fileSize;      // ファイルサイズ
    va_list vaList;      // 可変文字列
    int renewFile;       // ファイル作成し直し要否

    ret = pthread_mutex_lock(&mutexLog);

    memset(dateTime, 0x0, sizeof(dateTime));
    ret = getDateTime(LOG_DATETIME_FORMAT, sizeof(dateTime), dateTime);
    if (ret != 0)
    {
        return;
    }
    //  ファイル名の取得
    memset(fileName, 0x0, sizeof(fileName));
    sprintf(fileName, "%s/%s.log.%d", gIniValLog.logFilePathName, LOG_FILE_NAME, gLogCurNo);
    ret = stat(fileName, &stStat);
    if (ret != 0)
    {
        // error
        fileSize = 0;
    }
    else
    {
        fileSize = stStat.st_size;
    }

    // ファイルサイズのチェック
    renewFile = 0;

    if (fileSize >= gIniValLog.logFileSizeMax * LOG_FILE_SIZE_KB)
    {
        renewFile = 1;
        gLogCurNo++;
        if (gLogCurNo > gIniValLog.logFileNumMax)
        {
            gLogCurNo = 1;
        }
    }

    // ログファイル名の取得(フルパス)
    fp = NULL;
    if (renewFile == 0)
    {
        fp = fopen(fileName, "a");
    }
    else
    {
        // 新規ファイルの場合，gLogCurNoが更新されているため，fileNameを更新する
        sprintf(fileName, "%s/%s.log.%d", gIniValLog.logFilePathName, LOG_FILE_NAME, gLogCurNo);
        fp = fopen(fileName, "w");
    }

    if (fp == NULL)
    {
        // ファイルオープンエラーの場合
        // ログを出力しない
    }
    else
    {

        va_start(vaList, format);
        // 日時の出力
        fprintf(fp, "%s, ", dateTime);
        vfprintf(fp, format, vaList);
        fprintf(fp, "\n");
        va_end(vaList);

        ret = fclose(fp);
        if (ret == -1)
        {
            // file close error
        }
    }

    ret = pthread_mutex_unlock(&mutexLog);
    return;
}

/**
  * カレントログファイルの番号取得処理
  * 存在しているログファイルで更新日付が最新の拡張子番号をグローバル変数に設定する
  * ログファイルが存在しない場合は1を設定する
  */
void getCurrentLogFileNo(int fileType)
{
    int cnt;
    struct stat stStat;
    char fileName[2048];
    long fileUpdateTime;
    int fileNumMax = 0;
    char filePathName[1024];
    char fileNameBase[64];

    if (fileType == LOG_TYPE_APL)
    {
        gLogCurNo = 0;
        fileNumMax = gIniValLog.logFileNumMax;
        strcpy(filePathName, gIniValLog.logFilePathName);
        strcpy(fileNameBase, LOG_FILE_NAME);
    }

    // 更新日時が最新のファイルを取得
    fileUpdateTime = 0L;
    for (cnt = 0; cnt < fileNumMax; cnt++)
    {
        sprintf(fileName, "%s/%s.log.%d", filePathName, fileNameBase, cnt + 1);
        if ((stat(fileName, &stStat)) != 0)
        {
            // error
            continue;
        }

        if (stStat.st_mtime >= fileUpdateTime)
        {
            fileUpdateTime = stStat.st_mtime;
            switch (fileType)
            {
            case LOG_TYPE_APL:
            {
                gLogCurNo = cnt + 1;
                break;
            }
            }
        }
    }

    switch (fileType)
    {
    case LOG_TYPE_APL:
    {
        if (gLogCurNo == 0)
        {
            gLogCurNo = 1;
        }
        break;
    }
    }

    return;
}
