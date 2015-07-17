LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
	ext/glibc_openpty.c \
	walnut_console.c \
	nsexec.c \
	shared_ops.c \
	util.c \
	walnutd.c \
	array.c \
	walnut_config.c

LOCAL_MODULE := walnutd
LOCAL_MODULE_TAGS := optional
LOCAL_C_INCLUDES := \
	$(call include-path-for, libhardware_legacy)/hardware_legacy
LOCAL_SHARED_LIBRARIES := libm libcutils libc libhardware_legacy

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
	ext/glibc_openpty.c \
	walnut_console.c \
	shared_ops.c \
	util.c \
	walnut.c

LOCAL_MODULE:= walnut
LOCAL_MODULE_TAGS := optional
LOCAL_SHARED_LIBRARIES := libm libcutils libc

include $(BUILD_EXECUTABLE)
