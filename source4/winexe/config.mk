#################################
# Start BINARY winexe
[BINARY::winexe]
INSTALLDIR = BINDIR
PRIVATE_DEPENDENCIES = \
		POPT_SAMBA \
		POPT_CREDENTIALS \
		LIBPOPT \
		RPC_NDR_SVCCTL
# End BINARY winexe
#################################

winexe_OBJ_FILES = $(addprefix winexe/, \
		winexe.o \
		service.o \
		async.o \
		winexesvc/winexesvc32_exe.o \
		winexesvc/winexesvc64_exe.o )

winexe/winexesvc/winexesvc32_exe.c: winexe/winexesvc/winexesvc.c
	@$(MAKE) -C winexe/winexesvc

winexe/winexesvc/winexesvc64_exe.c: winexe/winexesvc/winexesvc.c
	@$(MAKE) -C winexe/winexesvc
