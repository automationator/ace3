function toggle_all_remediation_targets() {
    var checked = $("input[name='all_remediation_targets']").prop("checked");
    $("input[name$='remediation_target']").prop("checked", checked);
}

function remediation_targets(method, body, modal_id) {
    (function() {
        fetch('remediation_targets', {
            method: method,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
            credentials: 'same-origin'
        })
        .then(function(resp){
            if (!resp.ok) { return resp.text().then(function(t){ throw new Error(t || resp.statusText); }); }
            return resp.text();
        })
        .then(function(html){
            $(modal_id).html(html);
        })
        .catch(function(err){
            $(modal_id).modal('hide');
            alert('Failed to ' + method + ' remediation targets: ' + err.message);
        });
    })();
}

function get_remediation_targets() {
    var targets = Array();
    $("input[name^='remediation_target']").each(function(index) {
        if ($(this).is(":checked")) {
            targets.push({
                "name": atob($(this).attr("r_name")),
                "type": atob($(this).attr("r_type")),
                "value": atob($(this).attr("r_value"))
            })
        }
    });
    return targets;
}

function check_targets_selected(targets) {
    if (targets.length === 0) {
        alert("Select at least one remediation target");
        return false;
    }

    return true;
}

function show_remediation_targets(alert_uuids) {
    $('#remediation-selection-body').html('loading data...');
    $('#remediation-selection-modal').modal('show');
    remediation_targets("POST", {alert_uuids: alert_uuids}, '#remediation-selection-body');
}

function restore_remediation_targets() {
    targets = get_remediation_targets()
    if (! check_targets_selected(targets))
        return;

    $('#remediation-selection-modal').modal('hide');
    $('#remediation-body').html('restoring targets...');
    $('#remediation-modal').modal('show');
    remediation_targets("PUT", {targets: targets}, '#remediation-body');
}

function remove_remediation_targets() {
    targets = get_remediation_targets()
    if (! check_targets_selected(targets))
        return;

    $('#remediation-selection-modal').modal('hide');
    $('#remediation-body').html('removing targets...');
    $('#remediation-modal').modal('show');
    remediation_targets("DELETE", {targets: targets}, '#remediation-body');
}

function stop_remediation() {
    targets = get_remediation_targets();
    if (! check_targets_selected(targets))
        return;

    $('#remediation-body').html('stopping remediation...');
    $('#remediation-selection-modal').modal('hide');
    $('#remediation-modal').modal('show');
    remediation_targets("PATCH", {targets: targets, 'action': 'stop'}, '#remediation-body');
}

function delete_remediation() {
    targets = get_remediation_targets();
    if (! check_targets_selected(targets))
        return;

    $('#remediation-body').html('deleting remediation...');
    $('#remediation-selection-modal').modal('hide');
    $('#remediation-modal').modal('show');
    remediation_targets("PATCH", {targets: targets, 'action': 'delete'}, '#remediation-body');
}
