import pytest
from flask import url_for

from app.models import User
from saq.database import get_db
from saq.database.model import AuthGroup
from saq.database.util.user_management import add_user, delete_user
from saq.permissions.group import create_auth_group, delete_auth_group, add_user_to_auth_group
from saq.permissions.user import add_user_permission
from saq.constants import QUEUE_DEFAULT

pytestmark = pytest.mark.integration


@pytest.fixture
def test_user():
    """Create a test user for manage tests."""
    user = add_user(
        username="testuser",
        email="testuser@localhost",
        display_name="Test User",
        password="TestPass123!",
        queue=QUEUE_DEFAULT,
        timezone="UTC"
    )
    yield user
    delete_user("testuser")


@pytest.fixture
def disabled_user():
    """Create a disabled test user."""
    user = add_user(
        username="disableduser",
        email="disableduser@localhost",
        display_name="Disabled User",
        password="TestPass123!",
        queue=QUEUE_DEFAULT,
        timezone="UTC"
    )
    
    # Disable the user
    db_user = get_db().query(User).filter_by(username="disableduser").first()
    db_user.enabled = False
    get_db().commit()
    
    yield user
    delete_user("disableduser")


@pytest.fixture
def test_auth_group():
    """Create a test auth group."""
    group = create_auth_group("test_group")
    yield group
    delete_auth_group(group.id)


@pytest.fixture
def user_with_permissions(test_user):
    """Create a test user with specific permissions."""
    # Add some permissions to the user
    add_user_permission(test_user.id, "user", "read")
    add_user_permission(test_user.id, "user", "write")
    yield test_user


class TestManageUsers:
    """Test the manage_users view function."""
    
    def test_manage_users_get_request(self, web_client, test_user):
        """Test GET request to manage users page."""
        response = web_client.get(url_for('auth.manage_users'))
        
        assert response.status_code == 200
        assert b'User Management' in response.data
        assert b'Group Permission Management' in response.data
        assert test_user.username.encode() in response.data
    
    def test_manage_users_shows_enabled_users_by_default(self, web_client, test_user, disabled_user):
        """Test that enabled users are shown by default."""
        response = web_client.get(url_for('auth.manage_users'))
        
        assert response.status_code == 200
        assert test_user.username.encode() in response.data
        # Disabled user should still be shown without hide_disabled_users cookie
        assert disabled_user.username.encode() in response.data
    
    def test_manage_users_hides_disabled_users_with_cookie(self, web_client, test_user, disabled_user):
        """Test hiding disabled users when cookie is set."""
        web_client.set_cookie('hide_disabled_users', 'true')
        
        response = web_client.get(url_for('auth.manage_users'))
        
        assert response.status_code == 200
        assert test_user.username.encode() in response.data
        # Disabled user should not be shown when cookie is true
        assert disabled_user.username.encode() not in response.data
    
    def test_manage_users_shows_disabled_users_with_false_cookie(self, web_client, test_user, disabled_user):
        """Test showing disabled users when cookie is explicitly false."""
        web_client.set_cookie('hide_disabled_users', 'false')
        
        response = web_client.get(url_for('auth.manage_users'))
        
        assert response.status_code == 200
        assert test_user.username.encode() in response.data
        assert disabled_user.username.encode() in response.data
    
    def test_manage_users_includes_auth_groups(self, web_client, test_auth_group):
        """Test that auth groups are included in the response."""
        response = web_client.get(url_for('auth.manage_users'))
        
        assert response.status_code == 200
        assert test_auth_group.name.encode() in response.data
    
    def test_manage_users_includes_timezones(self, web_client):
        """Test that timezones are included in the response."""
        response = web_client.get(url_for('auth.manage_users'))
        
        assert response.status_code == 200
        # Check for some common timezones
        assert b'UTC' in response.data
        assert b'America/New_York' in response.data
    
    def test_manage_users_requires_permission(self, app):
        """Test that manage_users requires user read permission."""
        with app.test_client() as client:
            response = client.get(url_for('auth.manage_users'))
            
            # Should redirect to login due to missing permission
            assert response.status_code == 302
            assert 'login' in response.location


class TestGetUserDetails:
    """Test the get_user_details view function."""
    
    def test_get_user_details_single_user(self, web_client, user_with_permissions):
        """Test getting details for a single user."""
        response = web_client.get(url_for('auth.get_user_details', user_ids=str(user_with_permissions.id)))
        
        assert response.status_code == 200
        
        data = response.get_json()
        assert str(user_with_permissions.id) in data
        
        user_data = data[str(user_with_permissions.id)]
        assert user_data['username'] == user_with_permissions.username
        assert user_data['display_name'] == user_with_permissions.display_name
        assert user_data['email'] == user_with_permissions.email
        assert user_data['queue'] == user_with_permissions.queue
        assert user_data['timezone'] == user_with_permissions.timezone
        assert 'permissions' in user_data
        assert 'groups' in user_data
    
    def test_get_user_details_multiple_users(self, web_client, test_user, user_with_permissions):
        """Test getting details for multiple users."""
        user_ids = f"{test_user.id},{user_with_permissions.id}"
        response = web_client.get(url_for('auth.get_user_details', user_ids=user_ids))
        
        assert response.status_code == 200
        
        data = response.get_json()
        assert str(test_user.id) in data
        assert str(user_with_permissions.id) in data
        
        assert data[str(test_user.id)]['username'] == test_user.username
        assert data[str(user_with_permissions.id)]['username'] == user_with_permissions.username
    
    def test_get_user_details_with_groups(self, web_client, user_with_permissions, test_auth_group):
        """Test getting user details when user is in a group."""
        # Add user to the group
        add_user_to_auth_group(user_with_permissions.id, test_auth_group.id)
        
        response = web_client.get(url_for('auth.get_user_details', user_ids=str(user_with_permissions.id)))
        
        assert response.status_code == 200
        
        data = response.get_json()
        user_data = data[str(user_with_permissions.id)]
        
        # Check that groups are included
        assert len(user_data['groups']) > 0
        group_ids = [group['id'] for group in user_data['groups']]
        assert test_auth_group.id in group_ids
    
    def test_get_user_details_no_user_ids(self, web_client):
        """Test error when no user_ids provided."""
        response = web_client.get(url_for('auth.get_user_details'))
        
        assert response.status_code == 400
        
        data = response.get_json()
        assert 'error' in data
        assert 'no user ids provided' in data['error']
    
    def test_get_user_details_empty_user_ids(self, web_client):
        """Test error when empty user_ids provided."""
        response = web_client.get(url_for('auth.get_user_details', user_ids=''))
        
        assert response.status_code == 400
        
        data = response.get_json()
        assert 'error' in data
        assert 'no user ids provided' in data['error']
    
    def test_get_user_details_nonexistent_user(self, web_client):
        """Test handling of non-existent user ID."""
        # Use a very high ID that shouldn't exist
        response = web_client.get(url_for('auth.get_user_details', user_ids='999999'))
        
        assert response.status_code == 200
        
        data = response.get_json()
        # Should return empty dict for non-existent users
        assert data == {}
    
    def test_get_user_details_mixed_valid_invalid_ids(self, web_client, test_user):
        """Test mixing valid and invalid user IDs."""
        user_ids = f"{test_user.id},999999"
        response = web_client.get(url_for('auth.get_user_details', user_ids=user_ids))
        
        assert response.status_code == 200
        
        data = response.get_json()
        # Should only return data for valid user
        assert str(test_user.id) in data
        assert '999999' not in data
    
    def test_get_user_details_permissions_structure(self, web_client, user_with_permissions):
        """Test that permissions have correct structure."""
        response = web_client.get(url_for('auth.get_user_details', user_ids=str(user_with_permissions.id)))
        
        assert response.status_code == 200
        
        data = response.get_json()
        user_data = data[str(user_with_permissions.id)]
        
        # Check permissions structure
        permissions = user_data['permissions']
        assert isinstance(permissions, list)
        
        if permissions:  # If user has permissions
            perm = permissions[0]
            required_keys = ['major', 'minor', 'effect', 'source', 'group_id']
            for key in required_keys:
                assert key in perm
    
    def test_get_user_details_requires_permission(self, app):
        """Test that get_user_details requires user read permission."""
        with app.test_client() as client:
            response = client.get(url_for('auth.get_user_details', user_ids='1'))
            
            # Should redirect to login due to missing permission
            assert response.status_code == 302
            assert 'login' in response.location


class TestAddAuthGroup:
    """Test the add_auth_group view function."""
    
    def test_add_auth_group_success(self, web_client):
        """Test successfully adding a new auth group."""
        group_name = "new_test_group"
        
        response = web_client.post(url_for('auth.add_auth_group'), data={
            'add_auth_group_name': group_name
        })
        
        assert response.status_code == 302
        assert response.location.endswith(url_for('auth.manage_users'))
        
        # Check that group was created in database
        group = get_db().query(AuthGroup).filter(AuthGroup.name == group_name).first()
        assert group is not None
        assert group.name == group_name
        
        # Clean up
        delete_auth_group(group.id)
    
    def test_add_auth_group_duplicate_name(self, web_client, test_auth_group):
        """Test adding a group with an existing name (should be idempotent)."""
        response = web_client.post(url_for('auth.add_auth_group'), data={
            'add_auth_group_name': test_auth_group.name
        })
        
        assert response.status_code == 302
        assert response.location.endswith(url_for('auth.manage_users'))
        
        # Should still only be one group with this name
        groups = get_db().query(AuthGroup).filter(AuthGroup.name == test_auth_group.name).all()
        assert len(groups) == 1
    
    def test_add_auth_group_no_name(self, web_client):
        """Test error when no name provided."""
        response = web_client.post(url_for('auth.add_auth_group'), data={})
        
        assert response.status_code == 400
        
        data = response.get_json()
        assert 'error' in data
        assert 'no name provided' in data['error']
    
    def test_add_auth_group_empty_name(self, web_client):
        """Test error when empty name provided."""
        response = web_client.post(url_for('auth.add_auth_group'), data={
            'add_auth_group_name': ''
        })
        
        assert response.status_code == 400
        
        data = response.get_json()
        assert 'error' in data
        assert 'no name provided' in data['error']
    
    def test_add_auth_group_whitespace_name(self, web_client):
        """Test that whitespace name is accepted (current behavior)."""
        whitespace_name = "   "
        response = web_client.post(url_for('auth.add_auth_group'), data={
            'add_auth_group_name': whitespace_name
        })
        
        assert response.status_code == 400
        
        data = response.get_json()
        assert 'error' in data
        assert 'no name provided' in data['error']
    
    def test_add_auth_group_requires_permission(self, app):
        """Test that add_auth_group requires user write permission."""
        with app.test_client() as client:
            response = client.post(url_for('auth.add_auth_group'), data={
                'add_auth_group_name': 'test_group'
            })
            
            # Should redirect to login due to missing permission
            assert response.status_code == 302
            assert 'login' in response.location


class TestDeleteAuthGroups:
    """Test the delete_auth_groups view function."""
    
    def test_delete_auth_groups_single_group(self, web_client):
        """Test deleting a single auth group."""
        # Create a group to delete
        group = create_auth_group("group_to_delete")
        group_id = group.id  # Save ID before deletion
        
        response = web_client.post(
            url_for('auth.delete_auth_groups'),
            json={'groups': [group_id]},
            content_type='application/json'
        )
        
        assert response.status_code == 200
        
        data = response.get_json()
        assert 'success' in data
        assert 'permission groups deleted' in data['success']
        
        # Check that group was deleted from database
        get_db().expire_all()  # Refresh session to see database changes
        deleted_group = get_db().query(AuthGroup).filter(AuthGroup.id == group_id).first()
        assert deleted_group is None
    
    def test_delete_auth_groups_multiple_groups(self, web_client):
        """Test deleting multiple auth groups."""
        # Create groups to delete
        group1 = create_auth_group("group_to_delete_1")
        group2 = create_auth_group("group_to_delete_2")
        group1_id = group1.id  # Save IDs before deletion
        group2_id = group2.id
        
        response = web_client.post(
            url_for('auth.delete_auth_groups'),
            json={'groups': [group1_id, group2_id]},
            content_type='application/json'
        )
        
        assert response.status_code == 200
        
        data = response.get_json()
        assert 'success' in data
        assert 'permission groups deleted' in data['success']
        
        # Check that both groups were deleted
        get_db().expire_all()  # Refresh session to see database changes
        deleted_group1 = get_db().query(AuthGroup).filter(AuthGroup.id == group1_id).first()
        deleted_group2 = get_db().query(AuthGroup).filter(AuthGroup.id == group2_id).first()
        assert deleted_group1 is None
        assert deleted_group2 is None
    
    def test_delete_auth_groups_no_groups(self, web_client):
        """Test error when no group IDs provided."""
        response = web_client.post(
            url_for('auth.delete_auth_groups'),
            json={},
            content_type='application/json'
        )
        
        assert response.status_code == 400
        
        data = response.get_json()
        assert 'error' in data
        assert 'no group ids provided' in data['error']
    
    def test_delete_auth_groups_empty_groups_list(self, web_client):
        """Test error when empty groups list provided."""
        response = web_client.post(
            url_for('auth.delete_auth_groups'),
            json={'groups': []},
            content_type='application/json'
        )
        
        assert response.status_code == 400
        
        data = response.get_json()
        assert 'error' in data
        assert 'no group ids provided' in data['error']
    
    def test_delete_auth_groups_nonexistent_group(self, web_client):
        """Test deleting non-existent group (should not error)."""
        response = web_client.post(
            url_for('auth.delete_auth_groups'),
            json={'groups': [999999]},
            content_type='application/json'
        )
        
        assert response.status_code == 200
        
        data = response.get_json()
        assert 'success' in data
        assert 'permission groups deleted' in data['success']
    
    def test_delete_auth_groups_mixed_valid_invalid_ids(self, web_client):
        """Test deleting mix of valid and invalid group IDs."""
        # Create a group to delete
        group = create_auth_group("valid_group_to_delete")
        group_id = group.id  # Save ID before deletion
        
        response = web_client.post(
            url_for('auth.delete_auth_groups'),
            json={'groups': [group_id, 999999]},
            content_type='application/json'
        )
        
        assert response.status_code == 200
        
        data = response.get_json()
        assert 'success' in data
        assert 'permission groups deleted' in data['success']
        
        # Check that valid group was deleted
        get_db().expire_all()  # Refresh session to see database changes
        deleted_group = get_db().query(AuthGroup).filter(AuthGroup.id == group_id).first()
        assert deleted_group is None
    
    def test_delete_auth_groups_invalid_json(self, web_client):
        """Test error with invalid JSON payload."""
        response = web_client.post(
            url_for('auth.delete_auth_groups'),
            data="invalid json",
            content_type='application/json'
        )
        
        assert response.status_code == 400
    
    def test_delete_auth_groups_requires_permission(self, app):
        """Test that delete_auth_groups requires user write permission."""
        with app.test_client() as client:
            response = client.post(
                url_for('auth.delete_auth_groups'),
                json={'groups': [1]},
                content_type='application/json'
            )
            
            # Should redirect to login due to missing permission
            assert response.status_code == 302
            assert 'login' in response.location