
ifdef IQR_TOOLKIT_PATH
$(info ************ Run with Iqr toolkit **********)
export CGO_ENABLED=1
export CGO_CPPFLAGS=-I$(IQR_TOOLKIT_PATH)
ifeq ($(OS),Windows_NT)
	export CGO_LDFLAGS=$(IQR_TOOLKIT_PATH)/lib_x86_64/libiqr_toolkit_static.lib
else
	export CGO_LDFLAGS=$(IQR_TOOLKIT_PATH)/lib_x86_64/libiqr_toolkit.a
endif
else
$(info ****************** WARNING *********************)
$(info *          Run without Iqr toolkit             *)
$(info * set IQR_TOOLKIT_PATH to run with Iqr toolkit *)
$(info ************************************************)
export CGO_ENABLED=0
endif

all:
	go test -v .
