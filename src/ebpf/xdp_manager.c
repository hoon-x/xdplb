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
 * @file    xdp_manager.c
 * @author  JongHoon Shim (shim9532@gmail.com)
 * @date    2026.01.10
 * @brief   eBPF XDP 프로그램 관리 기능
*/

/*==== INCLUDES =============================================================*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include <math.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "xdp_manager.h"
#include "xdplb.skel.h"
#include "config.h"
#include "logger.h"
#include "cJSON.h"
#include "file.h"
#include "common/types.h"
#include "common/common.h"

/*==== LOCAL DEFINES ========================================================*/
/*==== LOCAL STRUCTS ========================================================*/
/*==== LOCAL VARIABLES ======================================================*/

static struct xdplb_bpf *g_skel = NULL;
static struct bpf_link *g_links[MAX_INTERFACES] = {0};

/*==== LOCAL FUNCTIONS DECLARATION ==========================================*/

static int bump_memlock_rlimit(void);
static int load_bpf_program(void);
static int attach_interfaces(void);
static void cleanup_xdp(void);
static int register_vip(const char *ip_str, uint16_t port, uint8_t proto, uint32_t vip_id);
static int update_vip_meta(const char *ip_str, uint16_t port, uint8_t proto, uint32_t real_count);
static int parse_mac_address(const char *mac_str, uint8_t *mac_out);
static int register_real_server(uint32_t vip_id, uint32_t index, const char *real_ip, uint16_t port, const char *mac_str);
static int load_lb_conf_from_file(void);
static void format_bytes(char *buf, size_t size, __u64 bytes);
static int get_global_stats(struct datarec *sum_rec);
static void log_stats(void);

/*==== FUNCTIONS ============================================================*/

/*!
 * @brief   eBPF XDP 관리 기능 메인
 * @return  int 성공 시 0, 실패 시 -1
*/
int run_xdp_manager(void)
{
    int err = -1;
    uint64_t cnt = 0;

    // MEMLOCK 제한 해제
    if (0 != bump_memlock_rlimit()) {
        return -1;
    }

    // BPF 프로그램 로드
    if (0 != load_bpf_program()) {
        return -1;
    }

    do {
        // VIP JSON 설정 파일 로드
        if (0 != load_lb_conf_from_file()) {
            break;
        }

        // 인터페이스에 XDP 부착
        if (0 != attach_interfaces()) {
            break;
        }

        LOGX_INFO("XDP Load Balancer is running...");

        while (g_config.running) {
            usleep(100000);
            if (g_config.debug) {
                if (0 == (++cnt % 10)) {
                    log_stats();
                }
            }
        }

        LOGX_INFO("Stopping XDP Load Balancer...");
        err = 0;
    } while (0);

    cleanup_xdp();

    return err;
}

/*!
 * @brief   MEMLOCK 제한 해제 함수
 * @return  int 성공 시 0, 실패 시 -1
*/
static int bump_memlock_rlimit(void)
{
    struct rlimit rlim_new = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY
    };

    if (0 != setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
        LOGX_ERROR("Failed to increase RLIMIT_MEMLOCK: %s", strerror(errno));
        return -1;
    }

    return 0;
}

/*!
 * @brief   BPF 프로그램 로드
 * @return  int 성공 시 0, 실패 시 -1
*/
static int load_bpf_program(void)
{   
    int err = 0;

    // 스켈레톤 열기
    g_skel = xdplb_bpf__open();
    if (NULL == g_skel) {
        LOGX_ERROR("Failed to open BPF skeleton");
        return -1;
    }

    // 로드 및 검증
    err = xdplb_bpf__load(g_skel);
    if (0 != err) {
        LOGX_ERROR("Failed to load BPF skeleton: %d", err);
        xdplb_bpf__destroy(g_skel);
        g_skel = NULL;
        return -1;
    }

    return 0;
}

/*!
 * @brief   등록된 네트워크 인터페이스별로 XDP를 붙여줌
 * @return  int 성공 시 0, 실패 시 -1
*/
static int attach_interfaces(void)
{
    int i = 0, ifindex = 0;
    const char *ifname = NULL;

    if (NULL == g_skel) {
        LOGX_ERROR("Invalid skeleton: IS NULL");
        return -1;
    }

    for (i = 0; i < g_config.if_count && i < MAX_INTERFACES; ++i) {
        ifindex = g_config.ifindices[i];
        ifname = g_config.ifnames[i];

        // XDP 프로그램 부착
        g_links[i] = bpf_program__attach_xdp(g_skel->progs.xdplb, ifindex);
        if (NULL == g_links[i]) {
            LOGX_ERROR("Failed to attach XDP to %s (idx: %d): %s",
                ifname, ifindex, strerror(errno));
            return -1;
        }

        LOGX_INFO("Attached XDP to %s (index: %d)", ifname, ifindex);
        SYSLOG_INFO("Attached XDP to %s (index: %d)", ifname, ifindex);
    }

    return 0;
}

/*!
 * @brief   XDP 프로그램 자원 정리
*/
static void cleanup_xdp(void)
{
    int i = 0;

    for (i = 0; i < MAX_INTERFACES; ++i) {
        if (NULL != g_links[i]) {
            bpf_link__destroy(g_links[i]);
            g_links[i] = NULL;
        }
    }

    if (NULL != g_skel) {
        xdplb_bpf__destroy(g_skel);
        g_skel = NULL;
    }
}

/*!
 * @brief   VIP(Virtual IP) 정보를 eBPF VIP 맵(Hash Map)에 등록
 * @details 사용자가 설정(JSON 등)에서 정의한 VIP 정보를 파싱하여 구조체를 구성하고,
 *          커널 영역의 BPF 맵(vip_map)에 업데이트.
 *          XDP 프로그램은 수신된 패킷의 목적지 IP/Port가 이 맵에 존재하는지 확인(Lookup)하여
 *          로드밸런싱 대상 여부를 결정.
 * @param   ip_str  VIP 주소 문자열 (예: "10.10.10.10")
 * @param   port    서비스 포트 번호 (Host Byte Order, 예: 8080)
 * @param   proto   L4 프로토콜 타입 (IPPROTO_TCP=6 또는 IPPROTO_UDP=17)
 * @param   vip_id  해당 VIP에 부여할 내부 고유 ID (Real Server 배열 인덱싱 계산에 사용됨)
 * @return  int     성공 시 0, 실패(파싱 오류, 맵 업데이트 실패 등) 시 -1
 */
static int register_vip(const char *ip_str, uint16_t port, uint8_t proto, uint32_t vip_id)
{
    struct vip_definition key = {0};
    struct vip_meta value = {0};
    int map_fd = -1;

    if (NULL == g_skel || NULL == ip_str) {
        return -1;
    }

    // Key 값 등록
    if (1 != inet_pton(AF_INET, ip_str, &key.vip)) {
        LOGX_ERROR("Invalid IP address format: %s", ip_str);
        return -1;
    }
    key.port = htons(port);
    key.proto = proto;

    // Value 값 등록
    value.vip_id = vip_id;
    value.real_count = 0;

    // VIP 맵(vip_map)의 파일 디스크립터(FD) 조회
    map_fd = bpf_map__fd(g_skel->maps.vip_map);
    if (map_fd < 0) {
        LOGX_ERROR("Failed to get vip_map FD");
        return -1;
    }

    // 구성한 Key/Value를 커널 맵에 등록
    // BPF_ANY: 이미 키가 존재하면 덮어쓰고, 없으면 새로 생성
    if (0 != bpf_map_update_elem(map_fd, &key, &value, BPF_ANY)) {
        LOGX_ERROR("Failed to register VIP %s:%d (proto:%d): %s",
            ip_str, port, proto, strerror(errno));
        return -1;
    }

    return 0;
}

/*!
 * @brief   VIP의 메타데이터(리얼 서버 개수) 갱신
 * @details 모든 리얼 서버 등록이 완료된 후, 해당 VIP에 연결된 리얼 서버의 총 개수(real_count)를 업데이트.
 *          단순히 덮어쓰는 것이 아니라, 기존에 수집된 트래픽 통계(rx_packets, rx_bytes)를 
 *          유지해야 하므로 'Lookup -> Modify -> Update' 과정을 거침.
 * @param   ip_str      VIP 주소 문자열
 * @param   port        서비스 포트 번호
 * @param   proto       L4 프로토콜 타입
 * @param   real_count  최종 등록된 리얼 서버의 총 개수
 * @return  int         성공 시 0, 실패 시 -1
 */
static int update_vip_meta(const char *ip_str, uint16_t port, uint8_t proto, uint32_t real_count)
{
    struct vip_definition v_key = {0};
    struct vip_meta v_meta = {0};
    int map_fd = -1;

    if (NULL == g_skel || NULL == ip_str) {
        return -1;
    }

    // VIP 맵 FD 획득
    map_fd = bpf_map__fd(g_skel->maps.vip_map);
    if (map_fd < 0) {
        LOGX_ERROR("Failed to get vip_map FD");
        return -1;
    }

    // Key 구성
    if (1 != inet_pton(AF_INET, ip_str, &v_key.vip)) {
        LOGX_ERROR("Invalid IP address format: %s", ip_str);
        return -1;
    }
    v_key.port = htons(port);
    v_key.proto = proto;

    // 기존 값 조회 (Lookup)
    if (0 != bpf_map_lookup_elem(map_fd, &v_key, &v_meta)) {
        LOGX_ERROR("VIP not found for update: %s:%d", ip_str, port);
        return -1;
    }

    // 리얼 서버 개수 갱신
    v_meta.real_count = real_count;
    if (0 != bpf_map_update_elem(map_fd, &v_key, &v_meta, BPF_EXIST)) {
        LOGX_ERROR("Failed to update VIP meta: %s", strerror(errno));
        return -1;
    }

    LOGX_INFO("VIP %s:%d ready with %d servers", ip_str, port, real_count);

    return 0;
}

/*!
 * @brief   MAC 주소 문자열 파싱 (String -> Byte Array)
 * @details "AA:BB:CC:11:22:33" 형식의 문자열을 파싱하여 6바이트 uint8_t 배열로 변환.
 *          sscanf의 %x 포맷을 사용하여 16진수 값을 읽음
 * @param   mac_str  MAC 주소 문자열 (예: "00:0c:29:36:09:78")
 * @param   mac_out  결과가 저장될 6바이트 배열 포인터 (Caller가 메모리 할당)
 * @return  int      성공 시 0, 형식이 일치하지 않거나 파싱 실패 시 -1
 */
static int parse_mac_address(const char *mac_str, uint8_t *mac_out)
{
    unsigned int values[6] = {0};
    int i = 0;

    if (NULL == mac_str || NULL == mac_out) {
        return -1;
    }

    // sscanf를 사용하여 ':'로 구분된 16진수 6개 파싱
    // %x: 16진수 정수 입력
    if (6 != sscanf(mac_str, "%x:%x:%x:%x:%x:%x",
                    &values[0], &values[1], &values[2],
                    &values[3], &values[4], &values[5]))
    {
        return -1; // 파싱 실패 (포맷 불일치)
    }

    // sscanf는 int(4byte)로 저장하므로, 이를 uint8_t(1byte)로 형변환하여 저장
    for (i = 0; i < 6; ++i) {
        mac_out[i] = (uint8_t)values[i];
    }
    return 0;
}

/*!
 * @brief   리얼 서버 정보를 eBPF 맵에 등록
 * @details 특정 VIP(vip_id)에 속한 N번째(index) 리얼 서버의 IP, Port, MAC 정보를
 *          'real_server_map' 배열 맵에 저장.
 *          DSR 모드에서 가장 중요한 것은 'MAC 주소'이며, Port는 보통 VIP 포트와 동일.
 * @param   vip_id   부모 VIP의 고유 ID
 * @param   index    해당 VIP 내에서의 순번 (0 ~ RealCount-1)
 * @param   real_ip  리얼 서버 IP 문자열
 * @param   port     리얼 서버 포트 (일반적으로 VIP 포트와 동일)
 * @param   mac_str  리얼 서버 물리 인터페이스의 MAC 주소 문자열
 * @return  int      성공 시 0, 실패 시 -1
 */
static int register_real_server(uint32_t vip_id, uint32_t index, const char *real_ip, uint16_t port, const char *mac_str)
{
    struct real_definition r_srv = {0};
    int real_map_fd = -1;
    uint32_t key = 0;

    if (NULL == g_skel || NULL == real_ip || NULL == mac_str) {
        return -1;
    }

    // 맵 FD 획득
    real_map_fd = bpf_map__fd(g_skel->maps.real_server_map);
    if (real_map_fd < 0) {
        LOGX_ERROR("Failed to get real_server_map FD");
        return -1;
    }
    
    // 맵 Key 계산 (Flat Array Indexing)
    // 2차원 배열(VIP -> Reals)을 1차원 배열 맵으로 표현하기 위한 인덱스 계산
    // 예: VIP_ID가 1이고 MAX가 16이면, 시작 인덱스는 16. (16 + 0, 16 + 1 ...)
    key = (vip_id * MAX_REAL_SERVERS) + index;
    
    // IP 주소 변환 (String -> Network Byte Order)
    if (1 != inet_pton(AF_INET, real_ip, &r_srv.ip)) {
        LOGX_ERROR("Invalid Real IP format: %s", real_ip);
        return -1;
    }
    
    // 인자로 받은 포트를 네트워크 바이트 순서로 변환
    r_srv.port = htons(port);
    
    // MAC 주소 파싱 및 저장
    // DSR 동작의 핵심인 Destination MAC 주소를 바이너리로 변환
    if (0 != parse_mac_address(mac_str, r_srv.mac)) {
        LOGX_ERROR("Invalid MAC address format: %s", mac_str);
        return -1;
    }

    // 맵 업데이트 (BPF_ANY: 생성 또는 갱신)
    if (0 != bpf_map_update_elem(real_map_fd, &key, &r_srv, BPF_ANY)) {
        LOGX_ERROR("Failed to register real server (Key:%u): %s", key, strerror(errno));
        return -1;
    }

    LOGX_INFO("Registered Real Server [VIP:%u Idx:%u] -> IP:%s Port:%d MAC:%s", 
              vip_id, index, real_ip, port, mac_str);

    return 0;
}

/*!
 * @brief   JSON 설정 파일 로드 및 LB 설정 적용
 * @details config.json 파일을 파싱하여 VIP 및 Real Server 정보를 BPF 맵에 등록
 * @return  int  성공 시 0, 실패 시 -1
 */
static int load_lb_conf_from_file(void)
{
    char *buf = NULL;
    cJSON *root_obj = NULL, *vips_obj = NULL, *vip_item = NULL;
    cJSON *vip_obj = NULL, *port_obj, *proto_obj = NULL;
    cJSON *reals_obj = NULL, *real_item = NULL, *ip_obj = NULL, *mac_obj = NULL;
    const char *vip_ip = NULL, *proto_str = NULL;
    const char *real_ip = NULL, *mac_str = NULL;
    uint8_t proto = 0;
    int port = 0;
    int vip_count = 0, i = 0, j = 0, tmp_err = 0, err = -1;
    int real_count = 0, vip_id = 0;

    // JSON 설정 파일 읽기 (메모리 할당)
    buf = read_text_file(LB_CONF_PATH);
    if (NULL == buf) {
        LOGX_ERROR("Failed to read load balance config file: %s", LB_CONF_PATH);
        return -1;
    } 

    do {
        // JSON 파싱
        root_obj = cJSON_Parse(buf);
        if (NULL == root_obj) {
            LOGX_ERROR("Failed to parse JSON syntax (Check config file format)");
            break;
        }

        // 'vips' 배열 찾기
        vips_obj = cJSON_GetObjectItem(root_obj, "vips");
        if (!cJSON_IsArray(vips_obj)) {
            LOGX_ERROR("Invalid config: 'vips' field is missing or not an array");
            break;
        }

        // 'vips' 배열 개수 획득
        vip_count = cJSON_GetArraySize(vips_obj);
        if (0 == vip_count) {
            LOGX_ERROR("Invalid config: 'vips' array is empty");
            break;
        }

        // VIP 목록 순회
        for (i = 0; i < vip_count; ++i) {
            // 'vips' 배열에서 i에 해당하는 아이템 획득
            vip_item = cJSON_GetArrayItem(vips_obj, i);
            if (NULL == vip_item) {
                LOGX_ERROR("Failed to get 'vips' array item: %d", i);
                tmp_err = -1;
                break;
            }

            // VIP IP 주소
            vip_obj = cJSON_GetObjectItem(vip_item, "vip");
            if (!cJSON_IsString(vip_obj) || NULL == vip_obj->valuestring) {
                LOGX_ERROR("VIP item #%d: 'vip' field is missing or invalid", i);
                tmp_err = -1;
                break;
            }
            vip_ip = vip_obj->valuestring;

            // Port 번호
            port_obj = cJSON_GetObjectItem(vip_item, "port");
            if (!cJSON_IsNumber(port_obj)) {
                LOGX_ERROR("VIP item #%d: 'port' field is missing or invalid", i);
                tmp_err = -1;
                break;
            }
            port = port_obj->valueint;
            if (port < 1 || port > 65535) {
                LOGX_ERROR("VIP item #%d: Invalid port number %d", i, port);
                tmp_err = -1;
                break;
            }

            // Protocol (TDP/UDP)
            proto_obj = cJSON_GetObjectItem(vip_item, "protocol");
            if (!cJSON_IsString(proto_obj) || NULL == proto_obj->valuestring) {
                LOGX_ERROR("VIP item #%d: 'protocol' field is missing", i);
                tmp_err = -1;
                break;
            }
            proto_str = proto_obj->valuestring;
            // 문자열을 상수(IPPROTO_*)로 변환
            proto = (0 == strcmp(proto_str, "udp")) ? IPPROTO_UDP : IPPROTO_TCP;

            // VIP ID는 설정 파일 순서(Index)를 사용 (0, 1, 2...)
            vip_id = i;

            // VIP 등록
            if (0 != register_vip(vip_ip, port, proto, vip_id)) {
                LOGX_ERROR("Failed to register VIP: %s", vip_ip);
                tmp_err = -1;
                break;
            }

            // Real Server 목록 파싱
            reals_obj = cJSON_GetObjectItem(vip_item, "reals");
            if (!cJSON_IsArray(reals_obj)) {
                LOGX_ERROR("VIP item #%d: 'reals' field is missing or not an array", i);
                tmp_err = -1;
                break;
            }

            // 'reals' 배열 원소 개수 획득
            real_count = cJSON_GetArraySize(reals_obj);
            if (0 == real_count) {
                LOGX_ERROR("VIP item #%d: No real servers defined in 'reals' array", i);
                tmp_err = -1;
                break;
            }

            for (j = 0; j < real_count; ++j) {
                // 'reals' 배열에서 j에 해당하는 아이템 추출
                real_item = cJSON_GetArrayItem(reals_obj, j);
                if (NULL == real_item) {
                    LOGX_ERROR("Failed to get 'relas' array item: %d", j);
                    tmp_err = -1;
                    break;
                }

                // Real IP
                ip_obj = cJSON_GetObjectItem(real_item, "ip");
                if (!cJSON_IsString(ip_obj) || NULL == ip_obj->valuestring) {
                    LOGX_ERROR("VIP #%d Real #%d: 'ip' field is missing", i, j);
                    tmp_err = -1;
                    break;
                }
                real_ip = ip_obj->valuestring;

                // Real MAC
                mac_obj = cJSON_GetObjectItem(real_item, "mac");
                if (!cJSON_IsString(mac_obj) || NULL == mac_obj->valuestring) {
                    LOGX_ERROR("VIP #%d Real #%d: 'mac' field is missing", i, j);
                    tmp_err = -1;
                    break;
                }
                mac_str = mac_obj->valuestring;

                // Real Server 등록 수행 (VIP ID, Index, IP, MAC)
                if (0 != register_real_server(vip_id, j, real_ip, port, mac_str)) {
                    LOGX_ERROR("Failed to register Real Server: %s", real_ip);
                    tmp_err = -1;
                    break;
                }
            }

            if (0 != tmp_err) {
                break;
            }

            // ----------------------------------------------------------------
            // [메타데이터 업데이트]
            // Real Server 등록이 모두 완료된 후, 총 개수(real_count)를 맵에 기록
            // ----------------------------------------------------------------
            if (0 != update_vip_meta(vip_ip, port, proto, real_count)) {
                LOGX_ERROR("Failed to update VIP meta info for %s", vip_ip);
                tmp_err = -1;
                break;
            }

            LOGX_INFO("Loaded VIP[%d] %s:%d (%s) with %d real servers", 
                      vip_id, vip_ip, port, proto_str, real_count);
        }

        if (0 != tmp_err) {
            break;
        }

        err = 0;
    } while (0);

    if (NULL != root_obj) {
        cJSON_Delete(root_obj);
    }
    free(buf);

    return err;
}

/*!
 * @brief   사람이 읽기 쉬운 데이터 단위(B, KB, MB...)로 변환
 * @details 바이트 수를 입력받아 가장 적절한 단위로 변환하여 문자열 버퍼에 저장
 * @param   buf     결과 문자열을 저장할 버퍼 포인터
 * @param   size    버퍼의 크기
 * @param   bytes   변환할 바이트 수
 */
static void format_bytes(char *buf, size_t size, __u64 bytes) 
{
    const char *suffixes[] = {"B", "KB", "MB", "GB", "TB"};
    int i = 0;
    double d_bytes = (double)bytes;

    while (d_bytes >= 1024 && i < 4) {
        d_bytes /= 1024;
        i++;
    }
    snprintf(buf, size, "%.2f %s", d_bytes, suffixes[i]);
}

/*!
 * @brief   Global 통계(전체 트래픽) 조회
 * @return  int 성공 시 0, 실패 시 -1
 */
static int get_global_stats(struct datarec *sum_rec)
{
    int map_fd = -1;
    int num_cpus = 0;
    int i = 0;
    struct datarec *values = NULL;
    __u32 key = 0; 

    if (NULL == g_skel || NULL == sum_rec) {
        return -1;
    }

    map_fd = bpf_map__fd(g_skel->maps.xdp_stats_map);
    if (map_fd < 0) {
        return -1;
    }

    // [중요] get_nprocs() 대신 libbpf가 제공하는 함수 사용
    // eBPF 맵은 'Possible CPU' 개수만큼 데이터를 반환하므로 이에 맞춰 할당해야 함
    num_cpus = libbpf_num_possible_cpus();
    if (num_cpus <= 0) {
        PRINT_ERROR("Failed to get possible CPU count");
        return -1;
    }
    
    // 메모리 할당
    values = calloc((size_t)num_cpus, sizeof(struct datarec));
    if (NULL == values) {
        PRINT_ERROR("Memory allocation failed");
        return -1;
    }

    // 맵 조회
    if (0 != bpf_map_lookup_elem(map_fd, &key, values)) {
        PRINT_ERROR("Failed to lookup global stats");
        free(values);
        return -1;
    }

    // 합산
    sum_rec->rx_packets = 0;
    sum_rec->rx_bytes = 0;
    for (i = 0; i < num_cpus; ++i) {
        sum_rec->rx_packets += values[i].rx_packets;
        sum_rec->rx_bytes   += values[i].rx_bytes;
    }

    free(values);
    return 0;
}

/*!
 * @brief   통계 로그 출력 (Log File Write)
 */
static void log_stats(void)
{
    int vip_map_fd = -1;
    struct datarec global_rec = {0};
    
    struct vip_definition key = {0};
    struct vip_definition next_key = {0};
    struct vip_definition *prev_key = NULL;
    struct vip_meta value = {0};
    
    char byte_str[32] = {0};
    char ip_str[INET_ADDRSTRLEN] = {0};
    const char *proto_str = NULL;

    // 1. Global Stats 로그
    if (0 == get_global_stats(&global_rec)) {
        format_bytes(byte_str, sizeof(byte_str), global_rec.rx_bytes);
        // 전체 통계 로그
        PRINT_DEBUG("[STATS-TOTAL] Pkts: %llu | Bytes: %s", 
                  global_rec.rx_packets, byte_str);
    }

    // 2. VIP Stats 순회 및 로그
    if (NULL == g_skel) {
        return;
    }

    vip_map_fd = bpf_map__fd(g_skel->maps.vip_map);
    if (vip_map_fd < 0) {
        return;
    }

    prev_key = NULL; 
    while (bpf_map_get_next_key(vip_map_fd, prev_key, &next_key) == 0) {
        if (0 == bpf_map_lookup_elem(vip_map_fd, &next_key, &value)) {
            inet_ntop(AF_INET, &next_key.vip, ip_str, sizeof(ip_str));
            format_bytes(byte_str, sizeof(byte_str), value.rx_bytes);
            proto_str = (next_key.proto == IPPROTO_TCP) ? "TCP" : 
                        (next_key.proto == IPPROTO_UDP) ? "UDP" : "UNK";

            // VIP 개별 통계 로그
            PRINT_DEBUG("[STATS-VIP] %s:%d(%s) | Pkts: %llu | Bytes: %s | Reals: %d",
                   ip_str, 
                   ntohs(next_key.port),
                   proto_str,
                   value.rx_packets,
                   byte_str,
                   value.real_count);
        }
        
        // Iterator Logic (Safe Copy)
        // 구조체 전체 복사 (Pointer assign이 아님)
        memcpy(&key, &next_key, sizeof(struct vip_definition));
        prev_key = &key;
    }
}
