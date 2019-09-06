/**
 * permissions related actions
 */

import Reflux from 'reflux';
import RefluxPromise from 'js/libs/reflux-promise';
Reflux.use(RefluxPromise(window.Promise));
import {dataInterface} from 'js/dataInterface';
import {
  t,
  notify
} from 'js/utils';

const permissionsActions = Reflux.createActions({
  getConfig: {children: ['completed', 'failed']},
  getAssetPermissions: {children: ['completed', 'failed']},
  getCollectionPermissions: {children: ['completed', 'failed']},
  bulkSetAssetPermissions: {children: ['completed', 'failed']},
  assignCollectionPermission: {children: ['completed', 'failed']},
  assignAssetPermission: {children: ['completed', 'failed']},
  removeAssetPermission: {children: ['completed', 'failed']},
  removePerm: {children: ['completed', 'failed']},
  copyPermissionsFrom: {children: ['completed', 'failed']},
  assignPublicPerm: {children: ['completed', 'failed']},
  setCollectionDiscoverability: {children: ['completed', 'failed']}
});

/**
 * New actions
 */

permissionsActions.getConfig.listen(() => {
  dataInterface.getPermissionsConfig()
    .done(permissionsActions.getConfig.completed)
    .fail(permissionsActions.getConfig.failed);
});

permissionsActions.getAssetPermissions.listen((assetUid) => {
  dataInterface.getAssetPermissions(assetUid)
    .done(permissionsActions.getAssetPermissions.completed)
    .fail(permissionsActions.getAssetPermissions.failed);
});

permissionsActions.getCollectionPermissions.listen((uid) => {
  dataInterface.getCollectionPermissions(uid)
    .done(permissionsActions.getCollectionPermissions.completed)
    .fail(permissionsActions.getCollectionPermissions.failed);
});

/**
 * For bulk setting permissions - wipes all current permissions, sets given ones
 *
 * @param {string} assetUid
 * @param {Object[]} perms - permissions to set
 */
permissionsActions.bulkSetAssetPermissions.listen((assetUid, perm) => {
  dataInterface.bulkSetAssetPermissions(assetUid, perm)
    .done(() => {
      permissionsActions.getAssetPermissions(assetUid);
      permissionsActions.bulkSetAssetPermissions.completed();
    })
    .fail(() => {
      permissionsActions.getAssetPermissions(assetUid);
      permissionsActions.bulkSetAssetPermissions.failed();
    });
});

/**
 * For adding single collection permission
 *
 * @param {string} uid - collection uid
 * @param {Object} perm - permission to add
 */
permissionsActions.assignCollectionPermission.listen((uid, perm) => {
  dataInterface.assignCollectionPermission(uid, perm)
    .done(() => {
      permissionsActions.getCollectionPermissions(uid);
      permissionsActions.assignCollectionPermission.completed();
    })
    .fail(() => {
      permissionsActions.getCollectionPermissions(uid);
      permissionsActions.assignCollectionPermission.failed();
    });
});

/**
 * For adding single asset permission
 *
 * @param {string} assetUid
 * @param {Object} perm - permission to add
 */
permissionsActions.assignAssetPermission.listen((assetUid, perm) => {
  dataInterface.assignAssetPermission(assetUid, perm)
    .done(() => {
      permissionsActions.getAssetPermissions(assetUid);
      permissionsActions.assignAssetPermission.completed();
    })
    .fail(() => {
      permissionsActions.getAssetPermissions(assetUid);
      permissionsActions.assignAssetPermission.failed();
    });
});

/**
 * For removing single permission
 *
 * @param {string} assetUid
 * @param {string} perm - permission url
 */
permissionsActions.removeAssetPermission.listen((assetUid, perm) => {
  dataInterface.removeAssetPermission(perm)
    .done(() => {
      permissionsActions.getAssetPermissions(assetUid);
      permissionsActions.removeAssetPermission.completed();
    })
    .fail(() => {
      notify(t('failed to remove permission'), 'error');
      permissionsActions.getAssetPermissions(assetUid);
      permissionsActions.removeAssetPermission.failed();
    });
});

/**
Old actions
 */

// copies permissions from one asset to other
permissionsActions.copyPermissionsFrom.listen(function(sourceUid, targetUid) {
  dataInterface.copyPermissionsFrom(sourceUid, targetUid)
    .done(() => {
      permissionsActions.getAssetPermissions(targetUid);
      permissionsActions.copyPermissionsFrom.completed(sourceUid, targetUid);
    })
    .fail(permissionsActions.copyPermissionsFrom.failed);
});

permissionsActions.removePerm.listen(function(details){
  if (!details.content_object_uid) {
    throw new Error('removePerm needs a content_object_uid parameter to be set');
  }
  dataInterface.removePerm(details.permission_url)
    .done(function(resp){
      permissionsActions.removePerm.completed(details.content_object_uid, resp);
    })
    .fail(function(resp) {
      permissionsActions.removePerm.failed(details.content_object_uid, resp);
      notify(t('Failed to remove permissions'), 'error');
    });
});

permissionsActions.setCollectionDiscoverability.listen(function(uid, discoverable){
  dataInterface.patchCollection(uid, {discoverable_when_public: discoverable})
    .done(permissionsActions.setCollectionDiscoverability.completed)
    .fail(permissionsActions.setCollectionDiscoverability.failed);
});

export default permissionsActions;
