import permConfig from './permConfig';
import {
  ANON_USERNAME,
  PERMISSIONS_CODENAMES
} from 'js/constants';
import {
  buildUserUrl,
  getUsernameFromUrl
} from 'js/utils';

/**
 * @typedef {Object} BackendPerm
 * @property {string} user - User url.
 * @property {string} permission - Permission url.
 */

/**
 * @typedef {Object} FormData  - Object containing data from the UserPermissionsEditor form.
 * @property {string} data.username - Who give permissions to.
 * @property {boolean} data.formView - Is able to view forms.
 * @property {boolean} data.formEdit - Is able to edit forms.
 * @property {boolean} data.submissionsView - Is able to view submissions.
 * @property {boolean} data.submissionsViewPartial - If true, then able to view submissions only of some users.
 * @property {string[]} data.submissionsViewPartialUsers - Users mentioned in the above line.
 * @property {boolean} data.submissionsAdd - Is able to add submissions.
 * @property {boolean} data.submissionsEdit - Is able to edit submissions.
 * @property {boolean} data.submissionsValidate - Is able to validate submissions.
 */

/**
 * Builds an object understandable by Backend endpoints from form data.
 *
 * @param {FormData} data
 * @returns {BackendPerm[]} - An array of permissions to be given.
 */
function parseFormData (data) {
  const parsed = [];

  if (data.formView) {
    parsed.push(buildBackendPerm(data.username, PERMISSIONS_CODENAMES.get('view_asset')));
  }

  if (data.formEdit) {
    parsed.push(buildBackendPerm(data.username, PERMISSIONS_CODENAMES.get('change_asset')));
  }

  if (data.submissionsViewPartial) {
    let permObj = buildBackendPerm(data.username, PERMISSIONS_CODENAMES.get('partial_submissions'));
    permObj.partial_permissions = [{
      url: permConfig.getPermissionByCodename(PERMISSIONS_CODENAMES.get('view_submissions')).url,
      filters: [{'_submitted_by': {'$in': data.submissionsViewPartialUsers}}]
    }];
    parsed.push(permObj);
  } else if (data.submissionsView) {
    parsed.push(buildBackendPerm(data.username, PERMISSIONS_CODENAMES.get('view_submissions')));
  }

  if (data.submissionsAdd) {
    parsed.push(buildBackendPerm(data.username, PERMISSIONS_CODENAMES.get('add_submissions')));
  }

  if (data.submissionsEdit) {
    parsed.push(buildBackendPerm(data.username, PERMISSIONS_CODENAMES.get('change_submissions')));
  }

  if (data.submissionsValidate) {
    parsed.push(buildBackendPerm(data.username, PERMISSIONS_CODENAMES.get('validate_submissions')));
  }

  // TODO 1: cleanup implied
  // TODO 2: cleanup contradictory

  return parsed;
}

function buildBackendPerm(username, permissionCodename) {
  return {
    user: buildUserUrl(username),
    permission: permConfig.getPermissionByCodename(permissionCodename).url
  };
}

/**
 * @param {UserPerm[]} permissions
 * @returns {FormData}
 */
function buildFormData(permissions) {
  const formData = {
    // username: '',
    // formView: false,
    // formEdit: false,
    // submissionsView: false,
    // submissionsViewPartial: false,
    // submissionsViewPartialUsers: [],
    // submissionsAdd: false,
    // submissionsEdit: false,
    // submissionsValidate: false,
  };

  permissions.forEach((perm) => {
    if (perm.permission === permConfig.getPermissionByCodename(PERMISSIONS_CODENAMES.get('view_asset')).url) {
      formData.formView = true;
    }
    if (perm.permission === permConfig.getPermissionByCodename(PERMISSIONS_CODENAMES.get('change_asset')).url) {
      formData.formEdit = true;
    }
    if (perm.permission === permConfig.getPermissionByCodename(PERMISSIONS_CODENAMES.get('partial_submissions')).url) {
      formData.submissionsViewPartial = true;
      formData.submissionsViewPartialUsers = perm.partial_permissions[0].filters._submitted_by.$in;
    }
    if (perm.permission === permConfig.getPermissionByCodename(PERMISSIONS_CODENAMES.get('add_submissions')).url) {
      formData.submissionsAdd = true;
    }
    if (perm.permission === permConfig.getPermissionByCodename(PERMISSIONS_CODENAMES.get('view_submissions')).url) {
      formData.submissionsView = true;
    }
    if (perm.permission === permConfig.getPermissionByCodename(PERMISSIONS_CODENAMES.get('change_submissions')).url) {
      formData.submissionsEdit = true;
    }
    if (perm.permission === permConfig.getPermissionByCodename(PERMISSIONS_CODENAMES.get('validate_submissions')).url) {
      formData.submissionsValidate = true;
    }
  });

  console.debug('buildFormData', permissions, formData);

  return formData;
}

/**
 * @typedef {Object} UserPerm
 * @property {string} url - Url of given permission instance (permission x user).
 * @property {string} name - Permission name.
 * @property {string} description - Permission user-friendly description.
 * @property {string} permission - Url of given permission type.
 */

/**
 * @typedef {Object} UserWithPerms
 * @property {Object} user
 * @property {string} user.url - User url (identifier).
 * @property {string} user.name - User name.
 * @property {boolean} user.isOwner - Marks user that owns an asset that the permissions are for.
 * @property {UserPerm[]} permissions - A list of permissions for that user.
 */

/**
 * Groups raw Backend permissions list data into array of users who have a list of permissions.
 *
 * @param {Object} data - Permissions array (results property from endpoint response).
 * @param {string} ownerUrl - Asset owner url (used as identifier).
 *
 * @returns {UserWithPerms[]} An list of users with all their permissions.
 */
function parseBackendData (data, ownerUrl) {
  const output = [];

  const groupedData = {};
  data.forEach((item) => {
    // anonymous user permissions are our inner way of handling public sharing
    // so we don't want to display them
    if (getUsernameFromUrl(item.user) === ANON_USERNAME) {
      return;
    }
    if (!groupedData[item.user]) {
      groupedData[item.user] = [];
    }
    const permDef = permConfig.getPermission(item.permission);
    groupedData[item.user].push({
      url: item.url,
      name: permDef.name || permDef.codename, // fallback to codename if empty string
      description: permDef.description,
      permission: item.permission,
      partial_permissions: item.partial_permissions ? item.partial_permissions : undefined
    });
  });

  Object.keys(groupedData).forEach((userUrl) => {
    output.push({
      user: {
        url: userUrl,
        name: getUsernameFromUrl(userUrl),
        // not all endpoints return user url in the v2 format, so as a fallback
        // we also check plain old usernames
        isOwner: (
          userUrl === ownerUrl ||
          getUsernameFromUrl(userUrl) === getUsernameFromUrl(ownerUrl)
        )
      },
      permissions: groupedData[userUrl]
    });
  });

  return output;
}

module.exports = {
  parseFormData: parseFormData,
  buildFormData: buildFormData,
  parseBackendData: parseBackendData
};
