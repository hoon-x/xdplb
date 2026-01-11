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
 * @file    common.h
 * @author  JongHoon Shim (shim9532@gmail.com)
 * @date    2026.01.10
 * @brief   유저 및 커널 공용 기능 헤더 파일
*/

#ifndef _COMMON_H
#define _COMMON_H

/*==== INCLUDES =============================================================*/

#include <linux/if_ether.h>

#include "types.h"

/*==== GLOBAL DEFINES =======================================================*/
/*==== GLOBAL STRUCTS =======================================================*/

// 전체 패킷 통계 정보 구조체
struct datarec {
    __u64 rx_packets;
    __u64 rx_bytes;
};

// VIP 식별을 위한 키 구조체 (IPv4 전용, 추후 IPv6 확장 가능)
struct vip_definition {
    __u32 vip;  // Virtual IP Address (Network Byte Order)
    __u16 port; // Port Number (Network Byte Order)
    __u8 proto; // Protocol (IPPROTO_TCP, IPPROTO_UDP)
    __u8 pad;   // Padding (구조체 정렬 및 해시 성능을 위해 필수)
};

// VIP 매칭 시 반환될 메타 데이터 구조체
struct vip_meta {
    __u64 rx_packets;   // 누적 패킷 개수
    __u64 rx_bytes;     // 누적 바이트 수
    __u32 vip_id;       // VIP의 고유 ID
    __u32 real_count;   // 현재 등록된 리얼 서버 개수
};

// 리얼 서버 정보 구조체
struct real_definition {
    __u32 ip;               // Real Server IP (Network Byte Order)
    __u16 port;             // Real Server Port (Network Byte Order)
    __u8 mac[ETH_ALEN];     // Real Server MAC Address (L2 포워딩용)
    __u8 pad[2];            // Padding
};

/*==== GLOBAL VARIABLES =====================================================*/
/*==== GLOBAL FUNCTIONS DECLARATION =========================================*/

#endif
