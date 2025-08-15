import logging
import uuid
from flask import jsonify, request
from flask_login import current_user
from app.auth.permissions import require_permission
from app.blueprints import auth
from saq.database.model import AuthGroupUser, AuthUserPermission, User
from saq.database.pool import get_db
from saq.permissions.group import add_group_permission, add_user_to_auth_group, delete_group_permission
from saq.permissions.user import UserPermission, add_user_permission, delete_user_permission
from saq.database.util.user_management import add_user as db_add_user

@auth.route('/auth/add', methods=['POST'])
@require_permission('user', 'edit')
def add_user():

    # POST json is a dict of the user details
    user: dict = request.get_json()

    # if the password is not provided, then generate a random one
    password = user.get("password")
    if not password:
        password = str(uuid.uuid4())

    new_user = db_add_user(
        username=user["username"],
        email=user["email"],
        display_name=user["display_name"],
        password=password,
        queue=user["queue"],
        timezone=user["timezone"]
    )

    # add the permissions defined in the request
    for permission in user["permissions"]:
        add_user_permission(new_user.id, permission["major"], permission["minor"], permission["effect"])

    # add the groups defined in the request
    for group_id in user["groups"]:
        add_user_to_auth_group(new_user.id, group_id)

    return jsonify({'success': 'User added successfully'}), 200

@auth.route('/auth/edit', methods=['POST'])
@require_permission('user', 'edit')
def edit_users():
    session = get_db()
    # users is a dict that maps user_id to the changes requested
    users: dict[int, dict] = request.get_json()

    # set to True if we're editing multiple users at once
    edit_multiple = len(users.items()) > 1

    for user_id, user_details in users.items():
        user = session.query(User).filter(User.id == user_id).first()
        if not user:
            return jsonify({'error': f'User {user_id} not found'}), 404

        # if we're editing a single user then we can edit the username, display name, and email address
        if not edit_multiple:
            if user_details.get("username"):
                user.username = user_details.get("username")
            if user_details.get("password"):
                user.password = user_details.get("password") # setter sets the password_hash
            if user_details.get("display_name"):
                user.display_name = user_details.get("display_name")
            if user_details.get("email"):
                user.email = user_details.get("email")

        if user_details.get("queue"):   
            user.queue = user_details.get("queue")
        if user_details.get("timezone"):
            user.timezone = user_details.get("timezone")
        if user_details.get("enabled") is not None:
            user.enabled = user_details.get("enabled")

        # if we're editing multiple users we're done here
        # if you want to mass-edit permissions, use permission groups
        #if edit_multiple:
            #continue

        if user_details.get("permissions"):

            # delete any existing permissions
            session.query(AuthUserPermission).filter(AuthUserPermission.user_id == user_id).delete()

            # add the permissions defined in the request
            for permission in user_details["permissions"]:
                add_user_permission(user_id, permission["major"], permission["minor"], permission["effect"], current_user.id)

        if user_details.get("groups"):

            # clear existing group memberships
            session.query(AuthGroupUser).filter(AuthGroupUser.user_id == user_id).delete()

            # add the groups defined in the request
            for group_id in user_details["groups"]:
                add_user_to_auth_group(user_id, group_id)

    session.commit()

    return jsonify({'success': 'Users updated successfully'}), 200

@auth.route('/auth/permission/add', methods=['POST'])
@require_permission('user', 'edit')
def add_permission():

    # POST json is a dict of the permission details
    permission: dict = request.get_json()

    for user_id in permission["users"]:
        add_user_permission(user_id, permission["major"], permission["minor"], permission["effect"], current_user.id)

    for group_id in permission["groups"]:
        add_group_permission(group_id, permission["major"], permission["minor"], permission["effect"], current_user.id)

    return jsonify({'success': 'Permission added successfully'}), 200

@auth.route('/auth/permission/delete', methods=['POST'])
@require_permission('user', 'edit')
def delete_permission():

    permissions: dict = request.get_json()

    for permission_id in permissions["users"]:
        delete_user_permission(permission_id)

    for permission_id in permissions["groups"]:
        delete_group_permission(permission_id)

    return jsonify({'success': 'Permission deleted successfully'}), 200