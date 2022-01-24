#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <pthread.h>
#include <stdarg.h>
#include <sys/time.h>
#include <time.h>

#include <rte_common.h>
#include <doca_log.h>

#include "logger.h"

DOCA_LOG_REGISTER(MPI_LOGGER);

// #define DEBUG

#define LOG_FILE_SIZE_KB 1024
// ログファイル名
#define LOG_FILE_NAME "mpipacket_analyze_test"
// バッファするログの数
#define LOG_BUF_LINE_MAX 1000
// ログ一行のサイズ上限 (EAGER_SENDのログが128byteだったため，余裕を持たせて150byteとした)
#define LOG_BUF_LINE_SIZE 150

// グローバル変数
// ログファイルNo 0:ファイル未確定 1以上:ファイル名確定中
int gLogCurNo;
// INI定義値(LOG)
INI_VALUE_LOG gIniValLog;

// ログファイル排他用ミューテックス
pthread_mutex_t mutexLog = PTHREAD_MUTEX_INITIALIZER;

// ログをファイル出力前に保存するバッファ
char mpilog_buf[LOG_BUF_LINE_MAX][LOG_BUF_LINE_SIZE];
int mpilog_buf_line_cnt = 0;

void init_mpilog_buf()
{
    memset(mpilog_buf, 0x0, sizeof(mpilog_buf));
}

// TODO: うまく動作しているか検証
// - 1件のログが生成される通信を行った後にmpiidを停止する．このとき，ログがファイルに出力されていることを確認する
void flush_mpilog_buf(uint32_t core_id)
{
    int ret;             // 戻り値
    FILE *fp;            // ファイルディスクプリタ
    char fileName[2048]; // ログファイル名

    ret = pthread_mutex_lock(&mutexLog);

    //  ファイル名の取得
    memset(fileName, 0x0, sizeof(fileName));
    sprintf(fileName, "%s/%s.log.%d", gIniValLog.logFilePathName, LOG_FILE_NAME, gLogCurNo);

    fp = fopen(fileName, "a");

    for (int i = 0; i < LOG_BUF_LINE_MAX; i++)
    {
        fprintf(fp, "%s", mpilog_buf[i]);
    }

    // ログバッファをクリア
    memset(mpilog_buf, 0x0, sizeof(mpilog_buf));
    mpilog_buf_line_cnt = 0;

    ret = fclose(fp);
    if (ret == -1)
    {
        // file close error
        DOCA_LOG_INFO("FILE CLOSE ERROR");
    }

    ret = pthread_mutex_unlock(&mutexLog);

    DOCA_LOG_DBG("core_id %u buffer is flushed!", core_id);
}

// TODO: BOFの危険あり．dateTimeLenで出力文字数の制限を行う．
int getDateTime(char *format, int dateTimeLen, char *dateTime)
{
    int ret = 0;
    struct timeval timevalData;
    struct tm timeData;

    ret = gettimeofday(&timevalData, NULL);
    if (ret == -1)
    {
        DOCA_LOG_INFO("gettimeofday ERROR");
        return -1;
    }

    if (localtime_r(&timevalData.tv_sec, &timeData) == NULL)
    {
        DOCA_LOG_INFO("localtime_r ERROR");
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

    memset(dateTime, 0x0, sizeof(dateTime));
    ret = getDateTime(LOG_DATETIME_FORMAT, sizeof(dateTime), dateTime);
    if (ret != 0)
    {
        return;
    }

#ifdef DEBUG
    struct timeval start;
    struct timeval end;
    gettimeofday(&start, NULL);
#endif
    // バッファに書き込み
    va_start(vaList, format);
    snprintf(mpilog_buf[mpilog_buf_line_cnt], LOG_BUF_LINE_SIZE, "%s, ", dateTime);
    vsnprintf(mpilog_buf[mpilog_buf_line_cnt] + strlen(mpilog_buf[mpilog_buf_line_cnt]), LOG_BUF_LINE_SIZE, format, vaList);
    snprintf(mpilog_buf[mpilog_buf_line_cnt] + strlen(mpilog_buf[mpilog_buf_line_cnt]), LOG_BUF_LINE_SIZE, "\n");
    va_end(vaList);
    mpilog_buf_line_cnt++;

#ifdef DEBUG
    gettimeofday(&end, NULL);
    float diff = end.tv_sec - start.tv_sec + (float)(end.tv_usec - start.tv_usec);
    DOCA_LOG_INFO("buffer writing time: %f[us]", diff);
#endif
    if (mpilog_buf_line_cnt < LOG_BUF_LINE_MAX)
    {
        // ログがLOG_BUF_LINE_MAX-1件まで溜まっていない場合には処理を終了する
        return;
    }

    ret = pthread_mutex_lock(&mutexLog);

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
        // ログをファイル出力
        for (int i = 0; i < LOG_BUF_LINE_MAX; i++)
        {
            fprintf(fp, "%s", mpilog_buf[i]);
        }

        // ログバッファをクリア
        memset(mpilog_buf, 0x0, sizeof(mpilog_buf));
        mpilog_buf_line_cnt = 0;

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
