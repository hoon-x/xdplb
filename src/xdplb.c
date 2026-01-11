/*
 * Copyright 2026 JongHoon Shim.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*==== FILE DESCRIPTION =====================================================*/

/*!
 * @file    xdplb.c
 * @author  JongHoon Shim (shim9532@gmail.com)
 * @date    2026.01.09
 * @brief   xdplb 소스 파일
*/

/*==== INCLUDES =============================================================*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <getopt.h>
#include <fcntl.h>
#include <syslog.h>
#include <sys/stat.h>
#include <net/if.h>

#include "config.h"
#include "logger.h"
#include "proc.h"
#include "common/types.h"
#include "xdp_manager.h"

/*==== LOCAL DEFINES ========================================================*/
/*==== LOCAL STRUCTS ========================================================*/
/*==== LOCAL VARIABLES ======================================================*/

static struct option g_options[] = {
    {"help",    no_argument,        0, 'h'},
    {"version", no_argument,        0, 'v'},
    {"iface",   required_argument,  0, 'i'},
    {0, 0, 0, 0}
};

config_t g_config;

/*==== LOCAL FUNCTIONS DECLARATION ==========================================*/

static void help(void);
static void version(void);
static int set_signal(void);
static void handle_signal(int sig);
static int change_cwd_to_executable_dir(void);
static int daemonize(void);
static bool is_running(pid_t *pid);
static pid_t get_pid_from_pid_file(void);
static int send_stop_signal(pid_t *pid);
static int write_own_pid_file(void);
static int parse_network_interfaces(const char *ifaces);

/*==== FUNCTIONS ============================================================*/

/*!
 * @brief   xdplb 메인 함수
 * @param   argc    인자값 개수
 * @param   argv    인자값
 * @return  int     정상 종료 0, 비정상 종료 1
*/
int main(int argc, char *argv[])
{
    int opt = -1, exit_code = 0;
    bool start = false, debug = false, stop = false;
    pid_t pid = 0;

    if (argc <= 1) {
        help();
        exit(0);
    }

    // CLI 옵션 처리
    while ((opt = getopt_long(argc, argv, "hvi:", g_options, NULL)) != -1) {
        switch (opt) {
            case 'h':
                help();
                exit(0);
            case 'v':
                version();
                exit(0);
            case 'i':
                // 네트워크 인터페이스 정보 파싱
                if (0 != parse_network_interfaces(optarg)) {
                    exit(1);
                }
                break;
            case '?':
            default:
                help();
                exit(0);
        }
    }

    // 명령어 존재여부 체크
    if (optind >= argc) {
        PRINT_WARN("Please input command: start|stop|debug");
        exit(0);
    }

    // 현재 작업 경로(CWD)를 실행 파일이 있는 경로로 변경
    if (0 != change_cwd_to_executable_dir()) {
        exit(1);
    }

    // 커맨드 저장
    start = (0 == strcmp("start", argv[optind])) ? true : false;
    debug = (0 == strcmp("debug", argv[optind])) ? true : false;
    stop = (0 == strcmp("stop", argv[optind])) ? true : false;

    if (start || debug) {
        // 프로세스가 이미 동작중인지 확인
        if (is_running(&pid)) {
            PRINT_INFO("%s already running (PID:%d)", MODULE_NAME, pid);
            exit(0);
        }

        // 옵션으로 네트워크 인터페이스 정보가 전달됐는지 검증
        if (0 == g_config.if_count) {
            PRINT_WARN("Interface is required. Usage: -i <ifname1>,<ifname2> ...");
            exit(0);
        }

        if (debug) {
            g_config.debug = true;
        }
    }
    else if (stop) {
        // 동작중인 프로세스에 종료 시그널 전송
        if (0 != send_stop_signal(&pid)) {
            PRINT_WARN("Failed to send SIGTERM (PID:%d)", pid);
        }
        exit(0);
    }
    else {
        PRINT_WARN("Invalid command: %s", argv[optind]);
        exit(0);
    }

    if (!g_config.debug) {
        // 프로세스 데몬화
        if (0 != daemonize()) {
            exit(1);
        }
        // 시스템 로그 초기화
        openlog(MODULE_NAME, LOG_PID, LOG_DAEMON);
    }

    g_config.pid = getpid();
    g_config.running = true;

    // 자신의 PID를 파일에 기록
    if (0 != write_own_pid_file()) {
        SYSLOG_ERROR("Failed to write PID file (%s)", PID_PATH);
        exit(1);
    }

    // 로거 초기화
    if (0 != init_logger(LOG_PATH, g_config.debug)) {
        SYSLOG_ERROR("Failed to initialize logger");
        exit(1);
    }

    // 시그널 설정
    if (0 != set_signal()) {
        LOGX_ERROR("Failed to set signal");
        exit(1);
    }

    // XDP 매니저 가동
    if (0 != run_xdp_manager()) {
        exit_code = 1;
    }

    // 로거 자원 정리
    destroy_logger();

    return exit_code;
}

/*!
 * @brief   도움말 출력
*/
static void help(void)
{
    printf("Usage: %s [command] [options]\n", MODULE_NAME);
    printf("Command: start|stop|debug\n");
    printf("Options:\n");
    printf("  -h, --help          show usage\n");
    printf("  -v, --version       show version\n");
    printf("  -i, --iface <list>  specify network interfaces (comma separated, e.g., eth0,eth1)\n");
}

/*!
 * @brief   버전 정보 출력
*/
static void version(void)
{
    printf("Build date: %s\n", BUILD_DATE);
    printf("%s version %s\n", MODULE_NAME, VERSION);
}


/*!
 * @brief   시그널 설정
 * @return  int 성공 시 0, 실패 시 -1
*/
static int set_signal(void)
{
    struct sigaction sa;
    size_t notify_signals[] = {
        SIGINT, SIGTERM
    };
    size_t ignore_signals[] = {
        SIGHUP, SIGPIPE, SIGTTIN, SIGTTOU, 
        SIGTSTP, SIGQUIT, SIGWINCH, SIGURG
    };
    size_t i = 0;

    // 핸들링할 시그널 설정
    memset(&sa, 0x00, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    for (i = 0; i < ARRAY_SIZE(notify_signals); ++i) {
        if (0 != sigaction(notify_signals[i], &sa, NULL)) {
            PRINT_ERROR("sigaction() failed: %s", strerror(errno));
            return -1;
        }
    }

    // 무시할 시그널 설정
    memset(&sa, 0x00, sizeof(sa));
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    for (i = 0; i < ARRAY_SIZE(ignore_signals); ++i) {
        if (0 != sigaction(ignore_signals[i], &sa, NULL)) {
            PRINT_ERROR("sigaction() failed: %s", strerror(errno));
            return -1;
        }
    }

    return 0;
}

/*!
 * @brief   시그널 핸들러
 * @param   sig 수신한 시그널 번호
*/
static void handle_signal(int sig)
{
    PRINT_INFO("Received signal: %s(%d)", strsignal(sig), sig);
    g_config.running = false;
}

/*!
 * @brief   현재 작업 경로(CWD)를 실행 파일이 있는 경로로 변경
 * @return  int 성공 시 0, 실패 시 -1
*/
static int change_cwd_to_executable_dir(void)
{   
    char exe_path[BUF_SIZE_1K] = {0};
    char *last_slash = NULL;
    ssize_t len = 0;

    // /proc/self/exe 심볼릭 링크를 읽어 실행 파일의 절대 경로를 가져옴
    len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (-1 == len) {
        PRINT_ERROR("Failed to read executable path: %s", strerror(errno));
        return -1;
    }

    // 디렉터리 추출
    last_slash = strrchr(exe_path, '/');
    if (NULL != last_slash) {
        // 실행 파일이 루트 바로 아래에 있는 경우
        if (last_slash == exe_path) {
            // '/'만 남김
            *(last_slash + 1) = '\0';
        }
        // 일반적인 경우 (예: /usr/bin/app)
        else {
            *last_slash = '\0';
        }
    }
    else {
        PRINT_ERROR("Invalid executable path format: %s", exe_path);
        return -1;
    }

    // 작업 디렉토리 변경
    if (0 != chdir(exe_path)) {
        PRINT_ERROR("Failed to change directory to '%s': %s", exe_path, strerror(errno));
        return -1;
    }

    return 0;
}

/*!
 * @brief   프로세스 데몬화 함수
 * @return  int 성공 시 0, 실패 시 -1
 */
static int daemonize(void)
{
    pid_t pid = 0;
    int fd = 0, err = -1;

    pid = fork();
    if (pid < 0) {
        PRINT_ERROR("fork() failed: %s", strerror(errno));
        return -1;
    }
    else if (pid > 0) {
        // 부모 프로세스 종료
        exit(0);
    }

    // 새로운 세션 리더 생성 (터미널 분리)
    setsid();
    
    // 파일 권한 마스크 초기화
    umask(0);

    // 상속된 FD들을 전부 닫아줌
    for (fd = 3; fd < 1024; ++fd) {
        close(fd);
    }

    // 표준 입출력, 에러를 /dev/null로 리다이렉트
    fd = open("/dev/null", O_RDWR);
    if (-1 == fd) {
        PRINT_ERROR("Failed to open `/dev/null`: %s", strerror(errno));
        return -1;
    }

    do {
        if (dup2(fd, STDIN_FILENO) < 0) {
            PRINT_ERROR("dup2(stdin) failed: %s", strerror(errno));
            break;
        }
        if (dup2(fd, STDOUT_FILENO) < 0) {
            PRINT_ERROR("dup2(stdout) failed: %s", strerror(errno));
            break;
        }
        if (dup2(fd, STDERR_FILENO) < 0) {
            PRINT_ERROR("dup2(stderr) failed: %s", strerror(errno));
            break;
        }

        err = 0;
    } while (0);

    if (fd > STDERR_FILENO) {
        close(fd);
    }

    return err;
}

/*!
 * @brief   이미 동작중인 프로세스가 존재하는지 확인
 * @param   pid     PID가 저장될 포인터
 * @return  bool    동작 중이면 true, 미동작 false
*/
static bool is_running(pid_t *pid)
{
    pid_t t_pid = 0;
    char proc_name[BUF_SIZE_128] = {0};

    // PID 파일에서 PID 추출
    t_pid = get_pid_from_pid_file();
    if (t_pid <= 1) {
        return false;
    }

    // 프로세스가 동작 중인지 확인
    if (!is_process_running(t_pid)) {
        return false;
    }

    // PID로부터 프로세스명 획득
    if (0 != get_proc_name_comm(t_pid, proc_name, sizeof(proc_name))) {
        return false;
    }

    // 내 모듈명과 프로세스명이 같은지 확인
    if (0 != strcmp(MODULE_NAME, proc_name)) {
        return false;
    }

    if (NULL != pid) {
        *pid = t_pid;
    }
    return true;
}

/*!
 * @brief   PID 파일에서 PID 값 추출
 * @return  pid_t   성공 시 PID, 실패 시 0
*/
static pid_t get_pid_from_pid_file(void)
{
    FILE *fp = NULL;
    char pid_buf[BUF_SIZE_128] = {0};
    pid_t pid = 0;

    fp = fopen(PID_PATH, "r");
    if (NULL == fp) {
        return 0;
    }

    fgets(pid_buf, sizeof(pid_buf), fp);
    fclose(fp);

    pid = (pid_t)atoi(pid_buf);
    return pid;
}

/*!
 * @brief   동작중인 모듈에 정지 신호 전송
 * @param   pid PID가 저장될 포인터
 * @return  int 성공 시 0, 실패 시 -1
*/
static int send_stop_signal(pid_t *pid)
{
    if (NULL == pid) {
        return -1;
    }

    //  프로세스가 동작중이지 않으면 성공 처리
    if (!is_running(pid)) {
        return 0;
    }

    // 유효하지 않은 PID는 실패 처리
    if (*pid <= 1) {
        return -1;
    }

    // 종료 시그널 전송
    if (0 != kill(*pid, SIGTERM)) {
        return -1;
    }

    return 0;
}

/*!
 * @brief   자신의 PID를 파일에 기록
 * @return  int 성공 시 0, 실패 시 -1
*/
static int write_own_pid_file(void)
{
    FILE *fp = NULL;

    if (0 != mkdir("var", 0755) && EEXIST != errno) {
        return -1;
    }

    fp = fopen(PID_PATH, "w");
    if (NULL == fp) {
        return -1;
    }

    fprintf(fp, "%d", g_config.pid);
    fclose(fp);

    return 0;
}

/*!
 * @brief   네트워크 인터페이스 옵션 파싱
 * @param   ifaces  CLI로 전달받은 인터페이스 문자열
 * @return  int     성공 시 0, 실패 시 -1
*/
static int parse_network_interfaces(const char *ifaces)
{
    char temp[BUF_SIZE_1K] = {0};
    char *token = NULL, *saveptr = NULL;

    if (NULL == ifaces || '\0' == *ifaces) {
        PRINT_ERROR("Invalid interface name: IS NULL");
        return -1;
    }

    strncpy(temp, ifaces, sizeof(temp) - 1);

    token = strtok_r(temp, ",", &saveptr);
    while (NULL != token) {
        // 최대 관리 가능한 인터페이스 개수 초과 여부 확인
        if (g_config.if_count >= MAX_INTERFACES) {
            PRINT_WARN("Too many interfaces. Limit is %d. Ignoring '%s'",
                MAX_INTERFACES, token);
            break;
        }

        // 파싱된 인터페이스 이름을 전역 설정 구조체에 저장
        strncpy(g_config.ifnames[g_config.if_count], token, sizeof(g_config.ifnames[g_config.if_count]) - 1);

        // 인터페이스 이름(문자열)을 커널 인덱스(정수)로 변환
        // XDP 프로그램은 인터페이스 이름이 아닌 인덱스(ifindex)를 사용하여 attach
        g_config.ifindices[g_config.if_count] = if_nametoindex(g_config.ifnames[g_config.if_count]);
        if (0 == g_config.ifindices[g_config.if_count]) {
            PRINT_ERROR("Invalid interface name: %s (System error: %s)",
                g_config.ifnames[g_config.if_count], strerror(errno));
            return -1;
        }

        // 정상 등록되었으므로 카운트 증가
        ++g_config.if_count;

        token = strtok_r(NULL, ",", &saveptr);
    }

    return 0;
}
