/*
   Unix SMB/CIFS implementation.
   async lookupname
   Copyright (C) Volker Lendecke 2009

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "winbindd.h"
#include "librpc/gen_ndr/cli_wbint.h"

struct wb_lookupname_state {
	struct dom_sid sid;
	enum lsa_SidType type;
};

static void wb_lookupname_done(struct tevent_req *subreq);

struct tevent_req *wb_lookupname_send(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      const char *dom_name, const char *name,
				      uint32_t flags)
{
	struct tevent_req *req, *subreq;
	struct wb_lookupname_state *state;
	struct winbindd_domain *domain;
	NTSTATUS status;

	req = tevent_req_create(mem_ctx, &state, struct wb_lookupname_state);
	if (req == NULL) {
		return NULL;
	}

	domain = find_lookup_domain_from_name(dom_name);
	if (domain == NULL) {
		DEBUG(5, ("Could not find domain for %s\n", dom_name));
		tevent_req_nterror(req, NT_STATUS_NONE_MAPPED);
		return tevent_req_post(req, ev);
	}

	status = wcache_name_to_sid(domain, dom_name, name,
				    &state->sid, &state->type);
	if (NT_STATUS_IS_OK(status)) {
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	subreq = rpccli_wbint_LookupName_send(
		state, ev, domain->child.rpccli, dom_name, name, flags,
		&state->type, &state->sid);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, wb_lookupname_done, req);
	return req;
}

static void wb_lookupname_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wb_lookupname_state *state = tevent_req_data(
		req, struct wb_lookupname_state);
	NTSTATUS status, result;

	status = rpccli_wbint_LookupName_recv(subreq, state, &result);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}
	if (!NT_STATUS_IS_OK(result)) {
		tevent_req_nterror(req, result);
		return;
	}
	tevent_req_done(req);
}

NTSTATUS wb_lookupname_recv(struct tevent_req *req, struct dom_sid *sid,
			    enum lsa_SidType *type)
{
	struct wb_lookupname_state *state = tevent_req_data(
		req, struct wb_lookupname_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	sid_copy(sid, &state->sid);
	*type = state->type;
	return NT_STATUS_OK;
}