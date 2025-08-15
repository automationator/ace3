from app.blueprints import auth
from flask import flash, jsonify, redirect, render_template, request, url_for
from app.auth.permissions import require_permission
from saq.database.model import AuthGroup, User
from saq.database.pool import get_db
from saq.permissions import get_user_permissions
from saq.permissions.group import (
    GroupPermission,
    create_auth_group,
    get_group_permissions,
    get_user_groups,
    delete_auth_group,
)
from saq.permissions.user import UserPermission

import pytz


@auth.route("/auth/manage", methods=["GET", "POST"])
@require_permission("user", "read")
def manage_users():
    # are we hiding disabled users?
    hide_disabled_users = request.cookies.get("hide_disabled_users", "false") == "true"

    query = get_db().query(User)
    if hide_disabled_users:
        query = query.filter(User.enabled == True)

    users: list[User] = query.all()
    permissions: dict[int, list[UserPermission]] = {}
    for user in users:
        permissions[user.id] = get_user_permissions(user.id)

    auth_groups: list[AuthGroup] = get_db().query(AuthGroup).all()
    group_permissions: dict[int, list[GroupPermission]] = {}
    for auth_group in auth_groups:
        group_permissions[auth_group.id] = get_group_permissions(auth_group.id)

    # get a list of all the available timezones
    timezones = pytz.all_timezones

    return render_template(
        "auth/manage.html",
        users=users,
        permissions=permissions,
        auth_groups=auth_groups,
        group_permissions=group_permissions,
        timezones=timezones,
        hide_disabled_users=hide_disabled_users,
    )


@auth.route("/auth/user", methods=["GET"])
@require_permission("user", "read")
def get_user_details():
    user_ids_text = request.args.get("user_ids")
    if not user_ids_text:
        return jsonify({"error": "no user ids provided"}), 400

    user_ids = [int(id) for id in user_ids_text.split(",")]

    users: list[User] = get_db().query(User).filter(User.id.in_(user_ids)).all()

    user_details = {}
    for user in users:
        permissions = [
            {
                "major": permission.major,
                "minor": permission.minor,
                "effect": permission.effect,
                "source": permission.source,
                "group_id": permission.group_id,
            }
            for permission in get_user_permissions(user.id, include_groups=False)
        ]

        groups = []
        for group in get_user_groups(user.id):
            groups.append(
                {
                    "id": group.id,
                    "name": group.name,
                }
            )

        user_details[user.id] = {
            "id": user.id,
            "username": user.username,
            "display_name": user.display_name,
            "email": user.email,
            "queue": user.queue,
            "timezone": user.timezone,
            "permissions": permissions,
            "groups": groups,
        }

    return jsonify(user_details)

@auth.route("/auth/group/add", methods=["POST"])
@require_permission("user", "write")
def add_auth_group():
    name = request.form.get("add_auth_group_name", "").strip()
    if not name:
        return jsonify({"error": "no name provided"}), 400

    create_auth_group(name)
    flash("permission group added")
    return redirect(url_for("auth.manage_users"))

@auth.route("/auth/group/delete", methods=["POST"])
@require_permission("user", "write")
def delete_auth_groups():
    request_json = request.get_json()
    group_ids = request_json.get("groups", [])
    if not group_ids:
        return jsonify({"error": "no group ids provided"}), 400

    for group_id in group_ids:
        delete_auth_group(group_id)

    return jsonify({'success': 'permission groups deleted'}), 200