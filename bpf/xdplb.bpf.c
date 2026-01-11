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
 * @file    xdplb.bpf.c
 * @author  JongHoon Shim (shim9532@gmail.com)
 * @date    2026.01.09
 * @brief   xdplb eBPF XDP 소스 파일
*/

/*==== INCLUDES =============================================================*/

#include <linux/types.h>
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "xdplb.bpf.h"
#include "jhash.h"

/*==== LOCAL DEFINES ========================================================*/
/*==== LOCAL STRUCTS ========================================================*/
/*==== LOCAL VARIABLES ======================================================*/
/*==== LOCAL FUNCTIONS DECLARATION ==========================================*/
/*==== FUNCTIONS ============================================================*/

/*!
 * @brief   이더넷(Ethernet) 헤더 파싱 및 프로토콜 타입 추출
 * @details 패킷의 시작 위치(커서)에서 이더넷 헤더를 읽어내고, 다음 계층(L3)의 프로토콜 타입 추출
 * @param   cursor      현재 패킷 파싱 위치(.pos)와 끝 지점(.end)을 관리하는 커서 구조체
 * @param   eth_proto   추출된 이더넷 프로토콜 타입이 저장될 변수 포인터 (Network Byte Order)
 * @return  int         성공 시 0, 패킷 길이가 너무 짧아 헤더를 읽을 수 없으면 -1
*/
static __always_inline int parse_eth(struct packet_cursor *cursor, __u16 *eth_proto)
{
    // 커서의 현재 위치를 이더넷 헤더 구조체 포인터로 캐스팅
    struct ethhdr *eth = cursor->pos;

    // 메모리 바운더리 체크 (Boundary Check)
    // (eth + 1)은 포인터 연산에 의해 '현재 위치 + sizeof(struct ethhdr)'
    // 즉, "이더넷 헤더의 끝지점"이 "패킷의 실제 끝(cursor->end)"을 넘어가는지 확인
    if ((void *)(eth + 1) > cursor->end) {
        return -1;
    }

    // 이더넷 프로토콜 필드 추출 (예: IPv4=0x0800, ARP=0x0806)
    *eth_proto = eth->h_proto;
    // 파싱 성공 후, 커서를 이더넷 헤더 크기만큼 뒤로 이동시킴 (Payload/L3 헤더 시작점)
    cursor->pos = (void *)(eth + 1);
    return 0;
}

/*!
 * @brief   IPv4 헤더 파싱 및 주소/프로토콜 정보 추출
 * @details 패킷에서 IPv4 헤더를 읽어내어 소스/목적지 IP와 상위 계층(L4) 프로토콜 타입 추출
 *          IPv4 헤더는 옵션 필드로 인해 길이가 가변적이므로, 이를 고려한 이중 메모리 검증
 * @param   cursor  현재 패킷 파싱 위치(.pos)와 끝 지점(.end)을 관리하는 커서 구조체
 * @param   proto   추출된 L4 프로토콜 타입 (예: TCP=6, UDP=17)
 * @param   src_ip  출발지 IP 주소 (Network Byte Order)
 * @param   dst_ip  목적지 IP 주소 (Network Byte Order)
 * @return  int     성공 시 0, 패킷이 너무 짧거나 잘못된 형식이면 -1
*/
static __always_inline int parse_ipv4(struct packet_cursor *cursor, __u8 *proto, __u32 *src_ip, __u32 *dst_ip)
{
    struct iphdr *iph = cursor->pos;

    // [1차 바운더리 체크: 고정 헤더 크기 검증]
    // IPv4 헤더의 필수 고정 크기(20바이트, sizeof(struct iphdr))가 패킷에 남아있는지 확인
    if ((void *)(iph + 1) > cursor->end) {
        return -1;
    }

    // [헤더 길이 계산]
    // IHL(Internet Header Length) 필드는 4비트로, 32비트(4바이트) 워드 단위의 길이
    // 따라서 실제 바이트 수는 (iph->ihl * 4)
    //  - 최소값: 5 (5 * 4 = 20 bytes, 옵션 없음)
    //  - 최대값: 15 (15 * 4 = 60 bytes)
    int ip_hdr_len = iph->ihl * 4;
    
    // [2차 바운더리 체크: 가변 길이 검증]
    // 계산된 실제 헤더 길이(ip_hdr_len)가 패킷의 끝을 넘어가는지 확인
    // 만약 IHL이 5보다 커서 옵션 필드가 존재하는데 패킷이 그만큼 길지 않다면, 잘못된 패킷
    if ((void *)iph + ip_hdr_len > cursor->end) {
        return -1;
    }

    // L4 프로토콜 추출
    *proto = iph->protocol;
    // 소스 IP 추출
    *src_ip = iph->saddr;
    // 목적지 IP 추출
    *dst_ip = iph->daddr;

    // [커서 이동]
    // 다음 파싱(L4 TCP/UDP)을 위해 커서를 IP 헤더의 '실제 크기(옵션 포함)'만큼 뒤로 이동
    cursor->pos = (void *)iph + ip_hdr_len;
    return 0;
}

/*!
 * @brief   L4(Transport Layer) 헤더 파싱 및 포트 번호 추출
 * @details 앞선 단계에서 식별된 프로토콜 타입(TCP/UDP)에 따라 적절한 헤더 파싱
 *          소스 포트와 목적지 포트를 추출하며, 프로토콜별 헤더 크기에 대한 메모리 검증
 * @param   cursor    현재 패킷 파싱 위치(.pos)와 끝 지점(.end)을 관리하는 커서 구조체
 * @param   proto     L3 헤더에서 추출한 상위 프로토콜 타입 (IPPROTO_TCP 또는 IPPROTO_UDP)
 * @param   src_port  출발지 포트 번호 (Network Byte Order)
 * @param   dst_port  목적지 포트 번호 (Network Byte Order)
 * @return  int       성공 시 0, 지원하지 않는 프로토콜이거나 패킷 길이가 부족하면 -1
 */
static __always_inline int parse_l4_ports(struct packet_cursor *cursor, __u8 proto, __u16 *src_port, __u16 *dst_port)
{
    // TCP
    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcph = cursor->pos;
        // [TCP 헤더 바운더리 체크]
        // TCP 헤더의 기본 크기(20바이트)가 유효한 메모리 범위 내에 있는지 확인
        if ((void *)(tcph + 1) > cursor->end) {
            return -1;
        }
        *src_port = tcph->source;
        *dst_port = tcph->dest;
    }
    // UDP
    else if (proto == IPPROTO_UDP) {
        struct udphdr *udph = cursor->pos;
        // [UDP 헤더 바운더리 체크]
        // UDP 헤더의 크기(8바이트)가 유효한지 확인
        if ((void *)(udph + 1) > cursor->end) {
            return -1;
        }
        *src_port = udph->source;
        *dst_port = udph->dest;
    } 
    else {
        // TCP나 UDP가 아닌 경우(예: ICMP, SCTP 등)는 현재 로드밸런싱 대상이 아니므로 실패 처리
        return -1; // 지원하지 않는 프로토콜
    }
    return 0;
}

/*!
 * @brief   패킷의 5-Tuple을 기반으로 해시 계산 (Jenkins Hash)
 * @details 소스 IP, 목적지 IP, 포트(Src/Dst), 프로토콜을 입력받아 32비트 해시값을 생성.
 *          Katran 등 고성능 로드밸런서에서 사용하는 'jhash_3words' 알고리즘을 사용하여,
 *          비트 단위의 미세한 변화(Avalanche Effect)도 해시 결과에 큰 영향을 주어 충돌 최소화.
 * @param   src_ip    출발지 IP 주소 (32bit, Network Byte Order)
 * @param   dst_ip    목적지 IP 주소 (32bit, Network Byte Order)
 * @param   src_port  출발지 포트 번호 (16bit)
 * @param   dst_port  목적지 포트 번호 (16bit)
 * @param   proto     L4 프로토콜 타입 (8bit, TCP/UDP 등)
 * @return  __u32     계산된 32비트 해시값 (이 값을 Real Server 개수로 모듈러 연산하여 인덱스 결정)
 */
static __always_inline __u32 get_packet_hash(__u32 src_ip, __u32 dst_ip, __u16 src_port, __u16 dst_port, __u8 proto)
{
    // [Word 1] Source IP (32비트)
    // IP 주소 자체를 첫 번째 해시 입력 워드로 사용.
    u32 a = src_ip;
    
    // [Word 2] Destination IP (32비트)
    // IP 주소 자체를 두 번째 해시 입력 워드로 사용.
    u32 b = dst_ip;
    
    // [Word 3] Ports Packing (16비트 + 16비트 = 32비트)
    // 두 개의 16비트 포트를 하나의 32비트 정수로 합침.
    // 예: SrcPort(8080=0x1F90), DstPort(1234=0x04D2)
    // (0x00001F90 << 16) | 0x000004D2
    // = 0x1F900000 | 0x000004D2
    // = 0x1F9004D2 (하나의 32비트 워드가 됨)
    u32 c = ((u32)src_port << 16) | dst_port;
    
    // [Initval] Protocol Mixing
    // 프로토콜(TCP=6, UDP=17)은 8비트이므로 별도의 워드로 쓰기엔 공간이 아까움.
    // 따라서 해시 함수의 초기값(Salt/Seed)에 더해주는 방식으로 믹싱에 참여.
    // 이렇게 하면 IP와 포트가 같아도 프로토콜이 다르면 전혀 다른 해시값이 나옴.
    u32 initval = proto;

    // [jhash_3words]
    // 준비된 3개의 32비트 워드(a, b, c)와 초기값(initval)을 이용해 최종 해시를 계산.
    // 내부적으로 비트 회전(Rotate)과 XOR 연산을 반복하여 무작위성을 확보.
    return jhash_3words(a, b, c, initval);
}

#if 0
/*!
 * @brief   Incremental Checksum Update (32비트 값 변경 시)
 * @details IP 주소 하나가 변경되었을 때, 전체 체크섬을 다시 계산하지 않고
 *          차이값(Delta)만 반영하여 빠르게 체크섬을 갱신 (RFC 1624)
 * @param   csum    갱신할 체크섬 필드의 포인터 (IP Checksum or L4 Checksum)
 * @param   old_val 변경 전 값 (Old IP)
 * @param   new_val 변경 후 값 (New IP)
 */
static __always_inline void csum_replace4(__u16 *csum, __u32 old_val, __u32 new_val)
{
    __u32 diff[] = {~old_val, new_val};
    __u64 sum = (__u64)~*csum & 0xFFFF; // 1의 보수로 변환

    // 차이값 더하기
    sum += bpf_csum_diff((void *)diff, sizeof(diff), NULL, 0, 0);
    
    // Carry bit 처리 (Wrap around)
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);

    *csum = ~((__u16)sum);
}
#endif

// XDP 프로그램 진입점
SEC("xdp")
int xdplb(struct xdp_md *ctx)
{
    // 포인터 초기화
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    __u16 eth_proto = 0;
    __u32 src_ip = 0, dst_ip = 0;
    __u16 src_port = 0, dst_port = 0;
    __u8  l4_proto = 0;

    struct packet_cursor cursor = {
        .pos = data, 
        .end = data_end
    };

    // 전체 통계 수집
    __u32 stats_key = 0;
    struct datarec *rec = bpf_map_lookup_elem(&xdp_stats_map, &stats_key);
    if (NULL != rec) {
        ++rec->rx_packets;
        rec->rx_bytes += (__u64)(data_end - data);
    }

    // [패킷 파싱 시작]
    // ========================================================================
    
    // Ethernet
    if (0 != parse_eth(&cursor, &eth_proto)) {
        return XDP_PASS; // 너무 짧은 패킷
    }

    // ARP 등은 패스 (IPv4만 처리: 0x0800)
    if (eth_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    // IPv4
    if (0 != parse_ipv4(&cursor, &l4_proto, &src_ip, &dst_ip)) {
        return XDP_PASS; // IP 헤더 에러
    }

    // TCP or UDP 프로토콜이 아니면 패스
    if (l4_proto != IPPROTO_TCP && l4_proto != IPPROTO_UDP) {
        return XDP_PASS;
    }

    // L4 Port
    if (0 != parse_l4_ports(&cursor, l4_proto, &src_port, &dst_port)) {
        return XDP_PASS;
    }

    // ========================================================================

    // [VIP Lookup]
    // ========================================================================

    // 패킷의 목적지 IP:Port 가 우리 VIP 테이블에 있는지 확인
    struct vip_definition vip_key = {
        .vip = dst_ip,
        .port = dst_port,
        .proto = l4_proto,
        .pad = 0
    };
    struct vip_meta *meta = bpf_map_lookup_elem(&vip_map, &vip_key);
    if (NULL == meta) {
        return XDP_PASS;
    }

    // 통계 업데이트
    __sync_fetch_and_add(&meta->rx_packets, 1);
    __sync_fetch_and_add(&meta->rx_bytes, (__u64)(data_end - data));

    // 리얼 서버가 하나도 없으면 패스
    if (0 == meta->real_count) {
        return XDP_PASS;
    }

    // ========================================================================

    // [로드 밸런싱]
    // ========================================================================

    // 패킷의 5-Tuple을 기반으로 해시 계산 (Jenkins Hash)
    u32 hash = get_packet_hash(src_ip, dst_ip, src_port, dst_port, l4_proto);

    // Round Robin (Modulo)
    // [TODO] Consistent Hashing (Maglev Hash) 구현
    // 현재 구현: 단순 Modulo 연산 (Round Robin)
    // - 방식: hash % real_count
    // - 문제점: 서버가 추가되거나 삭제되어 real_count가 변하면,
    //          기존 해시의 결과값이 대부분 바뀌어버림 (Reshuffling).
    //          이로 인해 기존에 연결된 TCP 세션들이 끊어지는 치명적 단점 존재.
    //
    // 향후 목표: Maglev Hashing (Katran 방식)
    // - 방식: 서버 개수보다 훨씬 큰 고정 크기의 Lookup Table (Ring)을 사용.
    //        예) Ring Size = 65537
    //        selected_index = Ring_Table[hash % 65537]
    // - 장점: 서버가 추가/삭제되어도 Ring Table의 일부 슬롯만 변경되므로,
    //        대부분의 트래픽은 기존 서버로 유지됨 (Connection Consistency 보장)
    u32 selected_index = hash % meta->real_count;
    u32 real_server_key = (meta->vip_id * MAX_REAL_SERVERS) + selected_index;

    // 리얼 서버 조회
    struct real_definition *real_server = bpf_map_lookup_elem(&real_server_map, &real_server_key);
    if (NULL == real_server) {
        return XDP_PASS;
    }

    // L2 DSR (MAC Address Modification Only)
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    // Source MAC Update
    // 패킷을 보내는 주체(나, LB)의 MAC으로 설정
    // 현재 eth->h_dest에는 나(LB)의 MAC이 들어있으므로 그걸 src_mac으로 사용
    __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);

    // Destination MAC Update
    // 선택된 리얼 서버의 MAC 주소로 설정
    __builtin_memcpy(eth->h_dest, real_server->mac, ETH_ALEN);

    // 5. 패킷 전송 (XDP_TX)
    // 들어온 인터페이스로 다시 내보냄
    // 만약 리얼 서버가 다른 인터페이스에 있다면 bpf_redirect_map을 써야 합니다.
    // 로컬 테스트용으로는 XDP_TX가 적절합니다.
    return XDP_TX;
    // ========================================================================
}

char _license[] SEC("license") = "GPL";
