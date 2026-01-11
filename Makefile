# ==========================================
#  XDPLB Project Makefile
# ==========================================

# 빌드 시간 정의
BUILD_DATE := $(shell date "+%Y-%m-%d\ %H:%M:%S")

# 컴파일러 및 플래그 설정
CLANG := clang
CC := gcc
BPFTOOL := bpftool

# eBPF 컴파일용 아키텍처 추출
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_M),x86_64)
	ARCH := x86
else ifeq ($(UNAME_M),aarch64)
	ARCH := arm64
else
	ARCH := $(UNAME_M)
endif

# 디렉터리 정의
SRC_DIR := src
BPF_DIR := bpf
INC_DIR := include
OBJ_DIR := obj
BIN_DIR := bin
CONF_DIR := conf

# 모듈명 정의
TARGET := xdplb
BPF_OBJ := xdplb.bpf.o
SKEL_H := xdplb.skel.h

# 소스 파일 및 오브젝트 파일 정의
# src 디렉터리 하위의 모든 .c 파일을 찾음
SRCS := $(shell find $(SRC_DIR) -name '*.c')
# 경로를 제거하고 파일명만 추출하여 obj 디렉터리에 .o로 매핑
OBJS := $(addprefix $(OBJ_DIR)/, $(notdir $(SRCS:.c=.o)))
# 의존성 파일 목록 정의
DEPS := $(OBJS:.o=.d)
# BPF 의존성 파일 목록 정의
BPF_DEP := $(OBJ_DIR)/$(BPF_OBJ:.o=.d)
# vpath를 설정하여 make가 src 하위 디렉터리에서도 .c 파일을 찾을 수 있게 함
vpath %.c $(sort $(dir $(SRCS)))

# 컴파일 플래그
CFLAGS := -O2 -Wall -Wextra -I$(INC_DIR) -I$(BPF_DIR) -MMD -MP
LDFLAGS := -lbpf -lelf -lz
DEFINES := -DBUILD_DATE=\"$(BUILD_DATE)\"

# BPF 컴파일 플래그
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -I$(INC_DIR) -MMD -MP -MF $(BPF_DEP)

# ==========================================
#  빌드 규칙 (Rules)
# ==========================================

.PHONY: all clean

all: $(BPF_DIR)/$(BPF_OBJ) $(BPF_DIR)/$(SKEL_H) $(BIN_DIR)/$(TARGET)

# BPF 오브젝트 빌드
$(BPF_DIR)/$(BPF_OBJ): $(BPF_DIR)/*.c | $(OBJ_DIR) $(BIN_DIR)
	@echo "[BPF] Building eBPF object: $@"
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "[CP] Copying $@ -> $(BIN_DIR)/"
	cp $@ $(BIN_DIR)/

# 스켈레톤 헤더 생성
$(BPF_DIR)/$(SKEL_H): $(BPF_DIR)/$(BPF_OBJ)
	@echo "[GEN] Generating skeleton header: $@"
	$(BPFTOOL) gen skeleton $< > $@

# 로더 링킹
$(BIN_DIR)/$(TARGET): $(OBJS) | $(BIN_DIR)
	@echo "[LINK] Linking application: $@"
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)
	cp -r $(CONF_DIR) $(BIN_DIR)

# 로더 소스 컴파일
$(OBJ_DIR)/%.o: %.c $(BPF_DIR)/$(SKEL_H) | $(OBJ_DIR)
	@echo "[CC] Compiling: $<"
	$(CC) $(CFLAGS) $(DEFINES) -c $< -o $@

# .d 파일을 include하여 make가 의존성을 알게 함
-include $(DEPS)
-include $(BPF_DEP)

# 디렉터리 생성 규칙
$(BIN_DIR) $(OBJ_DIR):
	@mkdir -p $@

clean:
	@echo "[CLEAN] Removing build artifacts..."
	rm -rf $(OBJ_DIR) $(BIN_DIR) $(BPF_DIR)/$(BPF_OBJ) $(BPF_DIR)/$(SKEL_H)
