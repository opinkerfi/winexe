/*
   Copyright (C) Andrzej Hajda 2009
   Contact: andrzej.hajda@wp.pl
   License: GNU General Public License version 3
*/

#include "includes.h"
#include "param/param.h"
#include "libcli/resolve/resolve.h"
#include "lib/cmdline/popt_common.h"
#include "librpc/rpc/dcerpc.h"
#include "librpc/gen_ndr/ndr_svcctl_c.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "lib/events/events.h"
//#define SERVICE_ALL_ACCESS (0xF01FF)
#define SERVICE_NO_CHANGE (0xffffffff)
#define SERVICE_INTERACTIVE_PROCESS (0x00000100)

#define SERVICE_STATE_ACTIVE (0x01)
#define SERVICE_STATE_INACTIVE (0x02)
#define SERVICE_STATE_ALL (0x03)
#define SERVICE_WIN32_OWN_PROCESS (0x00000010)
#define SERVICE_DEMAND_START (0x00000003)
#define SERVICE_ERROR_NORMAL (0x00000001)
#define SERVICE_CONTROL_STOP (0x00000001)
#define NT_STATUS_SERVICE_DOES_NOT_EXIST NT_STATUS(0xc0000424)
#include "system/filesys.h"
#include "libcli/libcli.h"
#include "libcli/smb_composite/smb_composite.h"
#include "lib/util/util.h"

#include "winexe.h"

#define NT_ERR(status, lvl, args...) if (!NT_STATUS_IS_OK(status)) { DEBUG(lvl,("ERROR: " args)); DEBUG(lvl,(". %s.\n", nt_errstr(status))); return status; }
#define NT_RES(status, werr) (NT_STATUS_IS_OK(status) ? werror_to_ntstatus(werr) : status)

NTSTATUS svc_pipe_connect(struct dcerpc_pipe **psvc_pipe,
			  const char *hostname,
			  struct cli_credentials *credentials)
{
	NTSTATUS status;
	char *binding;

	asprintf(&binding, "ncacn_np:%s%s", hostname, DEBUGLVL(9)?"[print]":"");
	status =
	    dcerpc_pipe_connect(NULL, psvc_pipe, binding,
				&ndr_table_svcctl, credentials, ev_ctx, cmdline_lp_ctx);
	free(binding);
	return status;
}

NTSTATUS svc_OpenSCManager(struct dcerpc_pipe * svc_pipe,
			   const char *hostname,
			   struct policy_handle * pscm_handle)
{
	NTSTATUS status;
	struct svcctl_OpenSCManagerW r;

	r.in.MachineName = hostname;
	r.in.DatabaseName = NULL;
	r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	r.out.handle = pscm_handle;
	status = dcerpc_svcctl_OpenSCManagerW(svc_pipe, NULL, &r);
	return NT_RES(status, r.out.result);
}

NTSTATUS svc_OpenService(struct dcerpc_pipe * svc_pipe,
			 struct policy_handle * pscm_handle,
			 const char *ServiceName,
			 struct policy_handle * psvc_handle)
{
	NTSTATUS status;
	struct svcctl_OpenServiceW r;

	r.in.scmanager_handle = pscm_handle;
	r.in.ServiceName = ServiceName;
	r.in.access_mask = SERVICE_ALL_ACCESS;
	r.out.handle = psvc_handle;
	status = dcerpc_svcctl_OpenServiceW(svc_pipe, NULL, &r);
	return NT_RES(status, r.out.result);
}

NTSTATUS svc_CreateService(struct dcerpc_pipe * svc_pipe,
			   struct policy_handle * pscm_handle,
			   const char *ServiceName,
			   uint32_t type,
			   const char *binary_path,
			   struct policy_handle * psvc_handle)
{
	NTSTATUS status;
	struct svcctl_CreateServiceW r;

	r.in.scmanager_handle = pscm_handle;
	r.in.ServiceName = ServiceName;
	r.in.DisplayName = NULL;
	r.in.desired_access = SERVICE_ALL_ACCESS;
	r.in.type = type;
	r.in.start_type = SERVICE_DEMAND_START;
	r.in.error_control = SERVICE_ERROR_NORMAL;
	r.in.binary_path = binary_path;
	r.in.LoadOrderGroupKey = NULL;
	r.in.TagId = NULL;
	r.in.dependencies = NULL;
	r.in.dependencies_size = 0;
	r.in.service_start_name = NULL;
	r.in.password = NULL;
	r.in.password_size = 0;
	r.out.handle = psvc_handle;
	r.out.TagId = NULL;
	status = dcerpc_svcctl_CreateServiceW(svc_pipe, NULL, &r);
	return NT_RES(status, r.out.result);
}

NTSTATUS svc_ChangeServiceConfig(struct dcerpc_pipe * svc_pipe,
                           struct policy_handle * psvc_handle,
			   uint32_t type,
                           const char *binary_path)
{
	NTSTATUS status;
	struct svcctl_ChangeServiceConfigW r;

	r.in.handle = psvc_handle;
	r.in.type = type;
	r.in.start_type = SERVICE_NO_CHANGE;
	r.in.error_control = SERVICE_NO_CHANGE;
	r.in.binary_path = binary_path;
	r.in.load_order_group = NULL;
	r.in.tag_id = NULL;
	r.in.dependencies = NULL;
	r.in.dependencies_size = 0;
	r.in.service_start_name = NULL;
	r.in.password = NULL;
	r.in.password_size = 0;
	r.in.display_name = NULL;
	r.out.tag_id = NULL;
	status = dcerpc_svcctl_ChangeServiceConfigW(svc_pipe, NULL, &r);
	return NT_RES(status, r.out.result);
}

NTSTATUS svc_StartService(struct dcerpc_pipe * svc_pipe,
			  struct policy_handle * psvc_handle)
{
	NTSTATUS status;
	struct svcctl_StartServiceW r;

	r.in.handle = psvc_handle;
	r.in.NumArgs = 0;
	r.in.Arguments = NULL;
	status = dcerpc_svcctl_StartServiceW(svc_pipe, NULL, &r);
	return NT_RES(status, r.out.result);
}

NTSTATUS svc_ControlService(struct dcerpc_pipe * svc_pipe,
			    struct policy_handle * psvc_handle,
			    int control, struct SERVICE_STATUS * sstatus)
{
	NTSTATUS status;
	struct svcctl_ControlService r;

	r.in.handle = psvc_handle;
	r.in.control = control;
	r.out.service_status = sstatus;
	status = dcerpc_svcctl_ControlService(svc_pipe, NULL, &r);
	return NT_RES(status, r.out.result);
}

NTSTATUS svc_QueryServiceStatus(struct dcerpc_pipe * svc_pipe,
			    struct policy_handle * psvc_handle,
			    struct SERVICE_STATUS * sstatus)
{
	NTSTATUS status;
	struct svcctl_QueryServiceStatus r;

	r.in.handle = psvc_handle;
	r.out.service_status = sstatus;
	status = dcerpc_svcctl_QueryServiceStatus(svc_pipe, NULL, &r);
	return NT_RES(status, r.out.result);
}

NTSTATUS svc_DeleteService(struct dcerpc_pipe * svc_pipe,
			   struct policy_handle * psvc_handle)
{
	NTSTATUS status;
	struct svcctl_DeleteService r;

	r.in.handle = psvc_handle;
	status = dcerpc_svcctl_DeleteService(svc_pipe, NULL, &r);
	return NT_RES(status, r.out.result);
}

NTSTATUS svc_CloseServiceHandle(struct dcerpc_pipe * svc_pipe,
				struct policy_handle * psvc_handle)
{
	NTSTATUS status;
	struct svcctl_CloseServiceHandle r;

	r.in.handle = psvc_handle;
	r.out.handle = psvc_handle;
	status = dcerpc_svcctl_CloseServiceHandle(svc_pipe, NULL, &r);
	return status;
}

NTSTATUS svc_UploadService(const char *hostname,
			   struct cli_credentials * credentials, int flags)
{
	struct smb_composite_savefile *io;
	struct smbcli_state *cli;
	NTSTATUS status;
	struct smbcli_options options;
	struct smbcli_session_options session_options;

	lp_smbcli_options(cmdline_lp_ctx, &options);
	lp_smbcli_session_options(cmdline_lp_ctx, &session_options);

	status =
	    smbcli_full_connection(NULL, &cli, hostname, lp_smb_ports(cmdline_lp_ctx), "ADMIN$", NULL,
				   lp_socket_options(cmdline_lp_ctx), credentials, lp_resolve_context(cmdline_lp_ctx), ev_ctx, &options, &session_options, lp_iconv_convenience(cmdline_lp_ctx), lp_gensec_settings(NULL, cmdline_lp_ctx));
	NT_ERR(status, 1, "Failed to open ADMIN$ share");
	if (flags & SVC_FORCE_UPLOAD) {
		smbcli_unlink(cli->tree, "winexesvc.exe");
	} else {
		int fd = smbcli_open(cli->tree, "winexesvc.exe", O_RDONLY, DENY_NONE);
		if (fd >= 0) {
			smbcli_close(cli->tree, fd);
			return status;
		}
	}
	io = talloc_zero(cli->tree, struct smb_composite_savefile);
	io->in.fname = "winexesvc.exe";
	if (flags & SVC_OSCHOOSE) {
	    status = smbcli_chkpath(cli->tree, "SysWoW64");
	}
	if ((flags & SVC_OSCHOOSE && NT_STATUS_IS_OK(status)) || (flags & SVC_OS64BIT)) {
		DEBUG(1, ("svc_UploadService: Installing 64bit winexesvc.exe\n"));
		io->in.data = winexesvc64_exe;
		io->in.size = winexesvc64_exe_len;
	} else {
		DEBUG(1, ("svc_UploadService: Installing 32bit winexesvc.exe\n"));
		io->in.data = winexesvc32_exe;
		io->in.size = winexesvc32_exe_len;
	}
	status = smb_composite_savefile(cli->tree, io);
	NT_ERR(status, 1, "Failed to save ADMIN$/%s", io->in.fname);
	talloc_free(io);
	smbcli_tdis(cli);
	return status;
}

/* Start, Creates, Install service if necccesary */
NTSTATUS svc_install(const char *hostname,
		     struct cli_credentials * credentials, int flags)
{
	NTSTATUS status;
	struct dcerpc_pipe *svc_pipe;
	struct policy_handle scm_handle;
	struct policy_handle svc_handle;
	int need_start;

	status = svc_pipe_connect(&svc_pipe, hostname, credentials);
	NT_ERR(status, 1, "Cannot connect to svcctl pipe");
	status = svc_UploadService(hostname, credentials, flags);
	NT_ERR(status, 1, "UploadService failed");
	status = svc_OpenSCManager(svc_pipe, hostname, &scm_handle);
	NT_ERR(status, 1, "OpenSCManager failed");
	status = svc_OpenService(svc_pipe, &scm_handle, "winexesvc",
				 &svc_handle);
	if (NT_STATUS_EQUAL(status, NT_STATUS_SERVICE_DOES_NOT_EXIST)) {
		status =
		    svc_CreateService(svc_pipe, &scm_handle, "winexesvc",
			SERVICE_WIN32_OWN_PROCESS | 
			(flags & SVC_INTERACTIVE ? SERVICE_INTERACTIVE_PROCESS : 0),
			"winexesvc.exe", &svc_handle);
		NT_ERR(status, 1, "CreateService failed");
		need_start = 1;
	} else if (NT_STATUS_IS_OK(status) && !(flags & SVC_IGNORE_INTERACTIVE)) {
		struct SERVICE_STATUS s;
		int what, want;
		status = svc_QueryServiceStatus(svc_pipe, &svc_handle, &s);
		NT_ERR(status, 1, "QueryServiceStatus failed");
		what = s.type & SERVICE_INTERACTIVE_PROCESS;
		want = flags & SVC_INTERACTIVE;
		if ((what && !want) || (!what && want)) {
			need_start = 1;
			if (s.state != SVCCTL_STOPPED) {
				status = svc_ControlService(svc_pipe, &svc_handle,
                                       SERVICE_CONTROL_STOP, &s);
				NT_ERR(status, 1, "StopService failed");
			}
			status = svc_ChangeServiceConfig(svc_pipe, &svc_handle, 
			    SERVICE_WIN32_OWN_PROCESS | 
			    (want ? SERVICE_INTERACTIVE_PROCESS : 0),
			    NULL);
			NT_ERR(status, 1, "ChangeServiceConfig failed");
			do {
			    msleep(100);
			    status = svc_QueryServiceStatus(svc_pipe, &svc_handle, &s);
			    NT_ERR(status, 1, "QueryServiceStatus failed");
			} while (s.state == SVCCTL_STOP_PENDING);
		}
	} else {
		NT_ERR(status, 1, "OpenService failed");
	}
	if ((flags & SVC_IGNORE_INTERACTIVE) || need_start) {
	    status = svc_StartService(svc_pipe, &svc_handle);
	    NT_ERR(status, 1, "StartService failed");
	}
	{
		struct SERVICE_STATUS s;
		do {
			msleep(100);
			status = svc_QueryServiceStatus(svc_pipe, &svc_handle, &s);
			NT_ERR(status, 1, "QueryServiceStatus failed");
		} while (s.state == SVCCTL_START_PENDING);
		if (s.state != SVCCTL_RUNNING) {
			DEBUG(0, ("Service cannot start, status=0x%08X\n", s.state));
			return NT_STATUS_UNSUCCESSFUL;
		}
	}
	svc_CloseServiceHandle(svc_pipe, &svc_handle);
	svc_CloseServiceHandle(svc_pipe, &scm_handle);
	talloc_free(svc_pipe);
	return status;
}

NTSTATUS svc_uninstall(const char *hostname,
		       struct cli_credentials * credentials)
{
	NTSTATUS status;
	struct dcerpc_pipe *svc_pipe;
	struct policy_handle scm_handle;
	struct policy_handle svc_handle;
	struct SERVICE_STATUS svc_status;
	struct smbcli_options options;
	struct smbcli_session_options session_options;

	lp_smbcli_options(cmdline_lp_ctx, &options);
	lp_smbcli_session_options(cmdline_lp_ctx, &session_options);

	status = svc_pipe_connect(&svc_pipe, hostname, credentials);
	NT_ERR(status, 1, "Cannot connect to svcctl pipe");
	status = svc_OpenSCManager(svc_pipe, hostname, &scm_handle);
	NT_ERR(status, 1, "OpenSCManager failed");
	status =
	    svc_OpenService(svc_pipe, &scm_handle, "winexesvc",
			    &svc_handle);
	NT_ERR(status, 1, "OpenService failed");
	DEBUG(1, ("OpenService - %s\n", nt_errstr(status)));
	if (NT_STATUS_IS_OK(status)) {
		status =
		    svc_ControlService(svc_pipe, &svc_handle,
				       SERVICE_CONTROL_STOP, &svc_status);
		{
			struct SERVICE_STATUS s;
			do {
				msleep(100);
				status = svc_QueryServiceStatus(svc_pipe, &svc_handle, &s);
				NT_ERR(status, 1, "QueryServiceStatus failed");
			} while (s.state == SVCCTL_STOP_PENDING);
			if (s.state != SVCCTL_STOPPED) {
				DEBUG(0, ("Service cannot stop, status=0x%08X\n", s.state));
				return NT_STATUS_UNSUCCESSFUL;
			}
		}
		DEBUG(1, ("StopService - %s\n", nt_errstr(status)));
		status = svc_DeleteService(svc_pipe, &svc_handle);
		DEBUG(1, ("DeleteService - %s\n", nt_errstr(status)));
		status = svc_CloseServiceHandle(svc_pipe, &svc_handle);
		DEBUG(1, ("CloseServiceHandle - %s\n", nt_errstr(status)));
	}
	svc_CloseServiceHandle(svc_pipe, &scm_handle);
	DEBUG(1, ("CloseSCMHandle - %s\n", nt_errstr(status)));

	struct smbcli_state *cli;
	status =
	    smbcli_full_connection(NULL, &cli, hostname, lp_smb_ports(cmdline_lp_ctx), "ADMIN$", NULL,
				   lp_socket_options(cmdline_lp_ctx), credentials, lp_resolve_context(cmdline_lp_ctx), ev_ctx, &options, &session_options, lp_iconv_convenience(cmdline_lp_ctx), lp_gensec_settings(NULL, cmdline_lp_ctx));
	NT_ERR(status, 1, "Failed to open ADMIN$ share");
	/* Give winexesvc some time to exit */
	msleep(300);
	status = smbcli_unlink(cli->tree, "winexesvc.exe");
	DEBUG(1, ("Delete winexesvc.exe - %s\n", nt_errstr(status)));
	status = smbcli_tdis(cli);
	DEBUG(1, ("Closing ADMIN$ - %s\n", nt_errstr(status)));
	return status;
}
