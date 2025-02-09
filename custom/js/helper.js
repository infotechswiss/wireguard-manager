function renderClientList(data) {
    $.each(data, function(index, obj) {
        // render client status css tag style
        let clientStatusHtml = '>'
        if (obj.Client.enabled) {
            clientStatusHtml = `style="visibility: hidden;">`
        }

        // render client allocated ip addresses
        let allocatedIpsHtml = "";
        $.each(obj.Client.allocated_ips, function(index, obj) {
            allocatedIpsHtml += `<small class="badge badge-secondary">${escapeHtml(obj)}</small>&nbsp;`;
        })

        // render client allowed ip addresses
        let allowedIpsHtml = "";
        $.each(obj.Client.allowed_ips, function(index, obj) {
            allowedIpsHtml += `<small class="badge badge-secondary">${escapeHtml(obj)}</small>&nbsp;`;
        })

        let subnetRangesString = "";
        if (obj.Client.subnet_ranges && obj.Client.subnet_ranges.length > 0) {
            subnetRangesString = obj.Client.subnet_ranges.join(',')
        }

        let additionalNotesHtml = "";
        if (obj.Client.additional_notes && obj.Client.additional_notes.length > 0) {
            additionalNotesHtml = `<div style="display: none"><i class="fas fa-additional_notes"></i>${escapeHtml(obj.Client.additional_notes.toUpperCase())}</div>`
        }

        // render client html content
        let html = `<div class="col-sm-6 col-md-6 col-lg-4" id="client_${obj.Client.id}">
                        <div class="card">
                            <div class="overlay" id="paused_${obj.Client.id}"` + clientStatusHtml
                                + `<i class="paused-client fas fa-3x fa-play" onclick="resumeClient('${obj.Client.id}')"></i>
                            </div>
                            <div class="card-header">
                                <div class="btn-group">
                                    <a href="download?clientid=${obj.Client.id}" class="btn btn-outline-primary btn-sm">Download</a>
                                </div>
                                <div class="btn-group">      
                                    <button type="button" class="btn btn-outline-primary btn-sm" data-toggle="modal"
                                        data-target="#modal_qr_client" data-clientid="${obj.Client.id}"
                                        data-clientname="${escapeHtml(obj.Client.name)}" ${obj.QRCode != "" ? '' : ' disabled'}>QR code</button>
                                </div>
                                <div class="btn-group">      
                                    <button type="button" class="btn btn-outline-primary btn-sm" data-toggle="modal"
                                        data-target="#modal_email_client" data-clientid="${obj.Client.id}"
                                        data-clientname="${escapeHtml(obj.Client.name)}">Email</button>
                                </div>
                                <div class="btn-group">
                                    <button type="button" class="btn btn-outline-danger btn-sm">More</button>
                                    <button type="button" class="btn btn-outline-danger btn-sm dropdown-toggle dropdown-icon" 
                                        data-toggle="dropdown">
                                    </button>
                                    <div class="dropdown-menu" role="menu">
                                        <a class="dropdown-item" href="#" data-toggle="modal"
                                        data-target="#modal_edit_client" data-clientid="${obj.Client.id}"
                                        data-clientname="${escapeHtml(obj.Client.name)}">Edit</a>
                                        <a class="dropdown-item" href="#" data-toggle="modal"
                                        data-target="#modal_pause_client" data-clientid="${obj.Client.id}"
                                        data-clientname="${escapeHtml(obj.Client.name)}">Disable</a>
                                        <a class="dropdown-item" href="#" data-toggle="modal"
                                        data-target="#modal_remove_client" data-clientid="${obj.Client.id}"
                                        data-clientname="${escapeHtml(obj.Client.name)}">Delete</a>
                                    </div>
                                </div>
                                </div>
                            <div class="card-body">
                                <div class="info-box-text"><i class="fas fa-user"></i> ${escapeHtml(obj.Client.name)}</div>
                                <div style="display: none"><i class="fas fa-key"></i> ${escapeHtml(obj.Client.public_key)}</div>
                                <div style="display: none"><i class="fas fa-subnetrange"></i>${escapeHtml(subnetRangesString)}</div>
                                ${additionalNotesHtml}
                                <div class="info-box-text"><i class="fas fa-envelope"></i> ${escapeHtml(obj.Client.email)}</div>
                                <div class="info-box-text"><i class="fas fa-clock"></i>
                                    ${prettyDateTime(obj.Client.created_at)}</div>
                                <div class="info-box-text"><i class="fas fa-history"></i>
                                    ${prettyDateTime(obj.Client.updated_at)}</div>
                                <div class="info-box-text"><i class="fas fa-server" style="${obj.Client.use_server_dns ? "opacity: 1.0" : "opacity: 0.5"}"></i>
                                    ${obj.Client.use_server_dns ? 'DNS enabled' : 'DNS disabled'}</div>
                                <div class="info-box-text"><i class="fas fa-file"></i>
                                    ${escapeHtml(obj.Client.additional_notes)}</div>
                                <div class="info-box-text"><strong>IP Allocation</strong></div>`
                                + allocatedIpsHtml
                                + `<div class="info-box-text"><strong>Allowed IPs</strong></div>`
                                + allowedIpsHtml
                            +`</div>
                        </div>
                    </div>`

        // add the client html elements to the list
        $('#client-list').append(html);
    });
}

function renderUserList(data) {
    $.each(data, function(index, obj) {
        let clientStatusHtml = '>'

        // render user html content
        let html = `<div class="col-sm-6 col-md-6 col-lg-4" id="user_${obj.username}">
                        <div class="card">
                            <div class="card-header">
                                <div class="btn-group">
                                     <button type="button" class="btn btn-outline-primary btn-sm" data-toggle="modal" data-target="#modal_edit_user" data-username="${obj.username}">Edit</button>
                                </div>
                                <div class="btn-group">
                                    <button type="button" class="btn btn-outline-danger btn-sm" data-toggle="modal"
                                        data-target="#modal_remove_user" data-username="${obj.username}">Delete</button>
                                </div>
                            </div>
                            <div class="card-body">
                                <div class="info-box-text"><i class="fas fa-user"></i> ${obj.username}</div>
                                <div class="info-box-text"><i class="fas fa-terminal"></i> ${obj.admin? 'Administrator':'Manager'}</div>
                            </div>
                        </div>
                    </div>`

        // add the user html elements to the list
        $('#users-list').append(html);
    });
}

function escapeHtml(unsafe) {
    return unsafe
         .replace(/&/g, "&amp;")
         .replace(/</g, "&lt;")
         .replace(/>/g, "&gt;")
         .replace(/"/g, "&quot;")
         .replace(/'/g, "&#039;");
 }

function prettyDateTime(timeStr) {
    const dt = new Date(timeStr);
    const offsetMs = dt.getTimezoneOffset() * 60 * 1000;
    const dateLocal = new Date(dt.getTime() - offsetMs);
    return dateLocal.toISOString().slice(0, 19).replace(/-/g, "/").replace("T", " ");
}
