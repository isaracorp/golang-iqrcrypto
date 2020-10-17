
ifdef IQR_TOOLKIT_PATH
$(info ************ Run with Iqr toolkit **********)
export CGO_ENABLED=1
export CGO_CPPFLAGS=-I$(IQR_TOOLKIT_PATH)
export CGO_LDFLAGS=$(IQR_TOOLKIT_PATH)/lib_x86_64/libiqr_toolkit.a
else
$(info ****************** WARNING *********************)
$(info *          Run without Iqr toolkit             *)
$(info * set IQR_TOOLKIT_PATH to run with Iqr toolkit *)
$(info ************************************************)
export CGO_ENABLED=0
endif

all:
	go test -v .
