TOP_DIR = $(PWD)
SIMENV_SYSROOT = $(TOP_DIR)/simenv

APP_NAME = 445.gobmk_ref
APP_CMD = ./gobmk_base.riscv --quiet --mode gtp < score2.tst
APP_INIT_CWD = /app
APP_MEMSIZE = 2048

SIM = spike
SIM_FLAGS = 
FESVR_FLAGS = 
PK_FLAGS = -c

SIM_FLAGS_EXTRA =
FESVR_FLAGS_EXTRA =
PK_FLAGS_EXTRA =
APP_CMD_EXTRA =

.PHONY: envsetup envcheck envclean run

define cmd_check
#ifeq (, $(shell 2>/dev/null which $1))
ifeq (,$(shell which $1))
$$(shell 1>&2 echo $2)
$$(error Cmd checking failed)
endif
endef

$(call cmd_check,atool-simenv,"Command 'atool-simenv' is not found. Did you installed the anycore-dbg-supplement with 'pip3 install --user anycore-dbg-supplement?'.")
$(call cmd_check,spike,"Command 'spike' is not found. Did you added RISCV toolchain to your path?")

envsetup:
	@ echo Setting up a new simenv at $(SIMENV_SYSROOT)
	atool-simenv spawn $(APP_NAME) $(SIMENV_SYSROOT)

envcheck:
	@ echo Verifing the simenv at $(SIMENV_SYSROOT)
	atool-simenv verify $(APP_NAME) $(SIMENV_SYSROOT)

envclean:
	@ echo Removing the simenv at $(SIMENV_SYSROOT)
	rm -frv $(SIMENV_SYSROOT)

run: envcheck
	echo sim
	cd $(TOP_DIR)/sysroot$(APP_INIT_CWD) && $(SIM) -m$(APP_MEMSIZE) $(SIM_FLAGS) $(SIM_FLAGS_EXTRA) $(FESVR_FLAGS) $(FESVR_FLAGS_EXTRA) +chroot=$(SIMENV_SYSROOT) pk $(PK_FLAGS) $(PK_FLAGS_EXTRA) $(APP_CMD) $(APP_CMD_EXTRA)
