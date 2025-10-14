from aceapi.auth import api_auth_check
from aceapi.blueprints import email_bp

import logging


from saq.constants import G_ENCRYPTION_KEY
from saq.email_archive import iter_archived_email, email_is_archived
from saq.environment import g

from flask import request, Response, abort


KEY_MESSAGE_ID = "message_id"

@email_bp.route('/get_archived_email', methods=['GET'])
@api_auth_check("email", "read")
def get_archived_email():
    if not g(G_ENCRYPTION_KEY):
        logging.critical("missing saq.ENCRYPTION_PASSWORD in api call to get_archived_email")
        abort(500)

    if KEY_MESSAGE_ID not in request.values:
        logging.warning("missing get parameter %s in api call to get_archived_email", KEY_MESSAGE_ID)
        abort(400)

    if not email_is_archived(request.values[KEY_MESSAGE_ID]):
        logging.info(f"email {request.values[KEY_MESSAGE_ID]} is not archived")
        abort(404)

    return Response(iter_archived_email(request.values[KEY_MESSAGE_ID]), mimetype="message/rfc822")
