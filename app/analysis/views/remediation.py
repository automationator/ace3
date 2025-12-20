from flask import render_template, request
from flask_login import current_user
from app.auth.permissions import require_permission
from app.blueprints import analysis
from saq.remediation.target import RemediationTarget, get_remediation_targets_by_alert_uuids
from saq.remediation.types import RemediationAction

@analysis.route('/remediation_targets', methods=['POST', 'PUT', 'DELETE', 'PATCH'])
@require_permission('remediation', 'read')
def remediation_targets():
    # get request body
    body = request.get_json()

    # return rendered target selection table
    if request.method == 'POST':
        targets = get_remediation_targets_by_alert_uuids(body['alert_uuids'])
        return render_template('analysis/remediation_targets.html', targets=targets)

    if request.method == 'PATCH':
        for target in body['targets']:
            if body['action'] == 'stop':
                RemediationTarget(remediator_name=target['name'], observable_type=target['type'], observable_value=target['value']).cancel_current_remediation()
                return 'remediation stopped', 200
            elif body['action'] == 'delete':
                RemediationTarget(remediator_name=target['name'], observable_type=target['type'], observable_value=target['value']).delete_current_remediation()
                return 'remediation deleted', 200

    # queue targets for removal/restoration
    action = RemediationAction.REMOVE if request.method == 'DELETE' else RemediationAction.RESTORE
    for target in body['targets']:
        RemediationTarget(remediator_name=target['name'], observable_type=target['type'], observable_value=target['value']).queue_remediation(action, current_user.id)

    return 'remediation queued', 200