/**
 * A bundle file for all Reflux actions. This is the only place that React
 * components should be talking to Backend.
 *
 * You can observe action result through Reflux callbacks in your component, or
 * more preferably (where applicable) use the update eveont of one of the stores
 * from `jsapp/js/stores.es6`
 *
 * TODO: Group and split actions to separate files. For a working example see `./actions/help`.
 */

import alertify from 'alertifyjs';
import Reflux from 'reflux';
import RefluxPromise from './libs/reflux-promise';
import {dataInterface} from './dataInterface';
import permissionsActions from './actions/permissions';
import {
  log,
  t,
  notify,
  replaceSupportEmail,
  redirectForAuthentication,
  checkCookieExists,
} from './utils';

// Configure Reflux
Reflux.use(RefluxPromise(window.Promise));

const actions = {
  permissions: permissionsActions,
  help: helpActions
};

actions.navigation = Reflux.createActions([
  'transitionStart',
  'transitionEnd',
  'routeUpdate',
  'documentTitleUpdate'
]);

actions.auth = Reflux.createActions({
  verifyLogin: {
    children: [
      'loggedin',
      'anonymous',
      'failed'
    ]
  },
  logout: {
    children: [
      'completed',
      'failed'
    ]
  },
  changePassword: {
    children: [
      'completed',
      'failed'
    ]
  },
  getEnvironment: {
    children: [
      'completed',
      'failed'
    ]
  },
  getApiToken: {
    children: [
      'completed',
      'failed'
    ]
  },
});

actions.survey = Reflux.createActions({
  addExternalItemAtPosition: {
    children: [
      'completed',
      'failed'
    ],
  }
});

actions.search = Reflux.createActions({
  assets: {
    children: [
      'completed',
      'failed'
    ]
  },
  collections: {
    children: [
      'completed',
      'failed'
    ]
  }
});

actions.resources = Reflux.createActions({
  listCollections: {
    children: [
      'completed',
      'failed'
    ]
  },
  createAsset: {
    children: [
      'completed',
      'failed'
    ]
  },
  createImport: {
    children: [
      'completed',
      'failed'
    ]
  },
  loadAsset: {
    children: [
      'completed',
      'failed'
    ]
  },
  deployAsset: {
    children: [
      'completed',
      'failed'
    ]
  },
  setDeploymentActive: {
    children: [
      'completed',
      'failed'
    ]
  },
  createSnapshot: {
    children: [
      'completed',
      'failed'
    ]
  },
  cloneAsset: {
    children: [
      'completed',
      'failed'
    ]
  },
  deleteAsset: {
    children: [
      'completed',
      'failed'
    ]
  },
  listTags: {
    children: [
      'completed',
      'failed'
    ]
  },
  createCollection: {
    children: [
      'completed',
      'failed'
    ]
  },
  updateCollection: {
    asyncResult: true
  },
  deleteCollection: {
    children: [
      'completed',
      'failed'
    ]
  },
  loadAssetSubResource: {
    children: [
      'completed',
      'failed'
    ]
  },
  loadAssetContent: {
    children: [
      'completed',
      'failed'
    ]
  },
  loadResource: {
    children: [
      'completed',
      'failed'
    ],
  },
  createResource: {
    asyncResult: true
  },
  updateAsset: {
    asyncResult: true
  },
  updateSubmissionValidationStatus: {
    children: [
      'completed',
      'failed'
    ],
  },
  removeSubmissionValidationStatus: {
    children: [
      'completed',
      'failed'
    ],
  },
  getAssetFiles: {
    children: [
      'completed',
      'failed'
    ],
  },
  notFound: {}
});

actions.hooks = Reflux.createActions({
  getAll: {children: ['completed', 'failed']},
  add: {children: ['completed', 'failed']},
  update: {children: ['completed', 'failed']},
  delete: {children: ['completed', 'failed']},
  getLogs: {children: ['completed', 'failed']},
  retryLog: {children: ['completed', 'failed']},
  retryLogs: {children: ['completed', 'failed']},
});

actions.misc = Reflux.createActions({
  checkUsername: {
    asyncResult: true,
    children: [
      'completed',
      'failed'
    ]
  },
  updateProfile: {
    children: [
      'completed',
      'failed'
    ]
  },
  getServerEnvironment: {
    children: [
      'completed',
      'failed',
    ]
  },
});

// TODO move these callbacks to `actions/permissions.es6` after moving
// `actions.resources` to separate file (circular dependency issue)
permissionsActions.assignAssetPermission.failed.listen(() => {
  notify(t('Failed to update permissions'), 'error');
});
permissionsActions.removeAssetPermission.failed.listen(() => {
  notify(t('Failed to remove permissions'), 'error');
});
permissionsActions.assignCollectionPermission.failed.listen(() => {
  notify(t('Failed to update permissions'), 'error');
});
permissionsActions.removeCollectionPermission.failed.listen(() => {
  notify(t('Failed to update permissions'), 'error');
});
permissionsActions.assignAssetPermission.completed.listen((uid) => {
  // needed to update publicShareSettings after enabling link sharing
  actions.resources.loadAsset({id: uid});
});
permissionsActions.copyPermissionsFrom.completed.listen((sourceUid, targetUid) => {
  actions.resources.loadAsset({id: targetUid});
});
permissionsActions.removeAssetPermission.completed.listen((uid) => {
  // needed to update publicShareSettings after disabling link sharing
  actions.resources.loadAsset({id: uid});
});
permissionsActions.setCollectionDiscoverability.completed.listen((val) => {
  actions.resources.loadAsset({url: val.url});
});

actions.misc.checkUsername.listen(function(username){
  dataInterface.queryUserExistence(username)
    .done(actions.misc.checkUsername.completed)
    .fail(actions.misc.checkUsername.failed);
});

actions.misc.updateProfile.listen(function(data, callbacks={}){
  dataInterface.patchProfile(data)
    .done((...args) => {
      actions.misc.updateProfile.completed(...args)
      if (callbacks.onComplete) {
        callbacks.onComplete(...args);
      }
    })
    .fail((...args) => {
      actions.misc.updateProfile.failed(...args)
      if (callbacks.onFail) {
        callbacks.onFail(...args);
      }
    });
});
actions.misc.updateProfile.completed.listen(function(){
  notify(t('updated profile successfully'));
});
actions.misc.updateProfile.failed.listen(function(data) {
  let hadFieldsErrors = false;
  for (const [errorProp, errorValue] of Object.entries(data.responseJSON)){
    if (errorProp !== 'non_fields_error') {
      hadFieldsErrors = true;
    }
  }

  if (hadFieldsErrors) {
    notify(t('Some fields contain errors'), 'error');
  } else {
    notify(t('failed to update profile'), 'error');
  }
});

actions.misc.getServerEnvironment.listen(function(){
  dataInterface.serverEnvironment()
    .done(actions.misc.getServerEnvironment.completed)
    .fail(actions.misc.getServerEnvironment.failed);
});

actions.resources.createImport.listen(function(contents){
  if (contents.base64Encoded) {
    dataInterface.postCreateImport(contents)
      .done(actions.resources.createImport.completed)
      .fail(actions.resources.createImport.failed);
  } else if (contents.content) {
    dataInterface.createResource(contents);
  }
});

actions.resources.createImport.completed.listen(function(contents){
  if (contents.status) {
    if(contents.status === 'processing') {
      notify(t('successfully uploaded file; processing may take a few minutes'));
      log('processing import ' + contents.uid, contents);
    } else {
      notify(t('unexpected import status ##STATUS##').replace('##STATUS##', contents.status), 'error');
    }
  } else {
    notify(t('Error: import.status not available'));
  }
});

actions.resources.createSnapshot.listen(function(details){
  dataInterface.createAssetSnapshot(details)
    .done(actions.resources.createSnapshot.completed)
    .fail(actions.resources.createSnapshot.failed);
});

actions.resources.listTags.listen(function(data){
  dataInterface.listTags(data)
    .done(actions.resources.listTags.completed)
    .fail(actions.resources.listTags.failed);
});

actions.resources.listTags.completed.listen(function(results){
  if (results.next && window.Raven) {
    Raven.captureMessage('MAX_TAGS_EXCEEDED: Too many tags');
  }
});

actions.resources.updateAsset.listen(function(uid, values, params={}) {
  if (checkCookieExists("__kpi_formbuilder")) {
    redirectForAuthentication();
} else {
  return new Promise(function(resolve, reject){
    dataInterface.patchAsset(uid, values)
      .done(function(asset){
        actions.resources.updateAsset.completed(asset);
        resolve(asset);
      })
      .fail(function(...args){
        reject(args)
      });
  }).then(function(asset) {
    var has_deployment = asset.has_deployment;
    var asset_type = asset.asset_type;
    if(asset_type === "survey") {
      dataInterface.deployAsset(asset, has_deployment)
        .done((data) => {
          if (has_deployment) {
            notify(t('Successfully updated published form.'));
          } else {
            notify(t('Successfully published form.'));
          }
        })
        .fail((data) => {
          if (data.status === 500) {
            alertify.error(t('Please add at least one question.'));
          } else {
            alertify.error(t(data.responseText));
          }
        });
    } else {
      notify(t(`Successfully updated ${asset_type}.`));
    }

    return asset
  })
}
});

actions.resources.deployAsset.listen(function(asset, redeployment, params={}){
  dataInterface.deployAsset(asset, redeployment)
    .done((data) => {
      actions.resources.deployAsset.completed(data.asset);
      if (typeof params.onDone === 'function') {
        params.onDone(data, redeployment);
      }
    })
    .fail((data) => {
      actions.resources.deployAsset.failed(data, redeployment);
      if (typeof params.onFail === 'function') {
        params.onFail(data,  redeployment);
      }
    });
});

actions.resources.deployAsset.failed.listen(function(data, redeployment){
  // report the problem to the user
  let failure_message = null;

  if(!data.responseJSON || (!data.responseJSON.xform_id_string &&
                            !data.responseJSON.detail)) {
    // failed to retrieve a valid response from the server
    // setContent() removes the input box, but the value is retained
    var msg;
    if (data.status == 500 && data.responseJSON && data.responseJSON.error) {
      msg = `<pre>${data.responseJSON.error}</pre>`;
    } else if (data.status == 500 && data.responseText) {
      msg = `<pre>${data.responseText}</pre>`;
    } else {
      msg = t('please check your connection and try again.');
    }
    failure_message = `
      <p>${replaceSupportEmail(t('if this problem persists, contact help@kobotoolbox.org'))}</p>
      <p>${msg}</p>
    `;
  } else if(!!data.responseJSON.xform_id_string){
    // TODO: now that the id_string is automatically generated, this failure
    // mode probably doesn't need special handling
    failure_message = `
      <p>${t('your form id was not valid:')}</p>
      <p><pre>${data.responseJSON.xform_id_string}</pre></p>
      <p>${replaceSupportEmail(t('if this problem persists, contact help@kobotoolbox.org'))}</p>
    `;
  } else if(!!data.responseJSON.detail) {
    failure_message = `
      <p>${t('your form cannot be deployed because it contains errors:')}</p>
      <p><pre>${data.responseJSON.detail}</pre></p>
    `;
  }
  alertify.alert(t('unable to deploy'), failure_message);
});

actions.resources.setDeploymentActive.listen(function(details) {
  dataInterface.setDeploymentActive(details)
    .done((data) => {
      actions.resources.setDeploymentActive.completed(data.asset);
    })
    .fail(actions.resources.setDeploymentActive.failed);
});
actions.resources.setDeploymentActive.completed.listen((result) => {
  if (result.deployment__active) {
    notify(t('Project unarchived successfully'));
  } else {
    notify(t('Project archived successfully'));
  }
});

actions.resources.getAssetFiles.listen(function(assetId) {
  dataInterface
    .getAssetFiles(assetId)
    .done(actions.resources.getAssetFiles.completed)
    .fail(actions.resources.getAssetFiles.failed);
});


actions.reports = Reflux.createActions({
  setStyle: {
    children: [
      'completed',
      'failed',
    ]
  },
  setCustom: {
    children: [
      'completed',
      'failed',
    ]
  }
});

actions.reports.setStyle.listen(function(assetId, details){
  dataInterface.patchAsset(assetId, {
    report_styles: JSON.stringify(details),
  }).done(actions.reports.setStyle.completed)
    .fail(actions.reports.setStyle.failed);
});

actions.reports.setCustom.listen(function(assetId, details){
  dataInterface.patchAsset(assetId, {
    report_custom: JSON.stringify(details),
  }).done(actions.reports.setCustom.completed)
    .fail(actions.reports.setCustom.failed);
});

actions.table = Reflux.createActions({
  updateSettings: {
    children: [
      'completed',
      'failed',
    ]
  }
});

actions.table.updateSettings.listen(function(assetId, settings){
  dataInterface.patchAsset(assetId, {
    settings: JSON.stringify(settings),
  }).done(actions.table.updateSettings.completed)
    .fail(actions.table.updateSettings.failed);
});


actions.map = Reflux.createActions({
  setMapSettings: {
    children: ['completed', 'failed']
  }
});

actions.map.setMapSettings.listen(function(assetId, details) {
  dataInterface
    .patchAsset(assetId, {
      map_styles: JSON.stringify(details)
    })
    .done(actions.map.setMapSettings.completed)
    .fail(actions.map.setMapSettings.failed);
});


actions.resources.createResource.listen(function(details){
  dataInterface.createResource(details)
    .done(function(asset){
      actions.resources.createResource.completed(asset);
      var asset_type = asset.asset_type;
      notify(t(`Successfully created ${asset_type}.`));
    })
    .fail(function(...args){
      actions.resources.createResource.failed(...args);
    });
});

actions.resources.deleteAsset.listen(function(details, params={}){
  dataInterface.deleteAsset(details)
    .done(() => {
      actions.resources.deleteAsset.completed(details);
      if (typeof params.onComplete === 'function') {
        params.onComplete(details);
      }
    })
    .fail((err) => {
      actions.resources.deleteAsset.failed(details);
      alertify.alert(
        t('Unable to delete asset!'),
        `<p>${t('Error details:')}</p><pre style='max-height: 200px;'>${err.responseText}</pre>`
      );
    });
});

actions.resources.deleteCollection.listen(function(details, params = {}){
  dataInterface.deleteCollection(details)
    .done(function(result) {
      actions.resources.deleteCollection.completed(details, result);
      if (typeof params.onComplete === 'function') {
        params.onComplete(details, result);
      }
    })
    .fail(actions.resources.deleteCollection.failed);
});
actions.resources.deleteCollection.failed.listen(() => {
  notify(t('Failed to delete collection.'), 'error');
});

actions.resources.updateCollection.listen(function(uid, values){
  dataInterface.patchCollection(uid, values)
    .done(function(asset){
      actions.resources.updateCollection.completed(asset);
      notify(t('successfully updated'));
    })
    .fail(function(...args){
      actions.resources.updateCollection.failed(...args);
    });
});

actions.resources.cloneAsset.listen(function(details, params={}){
  dataInterface.cloneAsset(details)
    .done((asset) => {
      actions.resources.cloneAsset.completed(asset);
      if (typeof params.onComplete === 'function') {
        params.onComplete(asset);
      }
    })
    .fail(actions.resources.cloneAsset.failed);
});
actions.resources.cloneAsset.failed.listen(() => {
  notify(t('Could not create project!'), 'error');
});

actions.search.assets.listen(function(searchData, params={}){
  dataInterface.searchAssets(searchData)
    .done(function(response){
      actions.search.assets.completed(searchData, response);
      if (typeof params.onComplete === 'function') {
        params.onComplete(searchData, response);
      }
    })
    .fail(function(response){
      actions.search.assets.failed(searchData, response);
      if (typeof params.onFailed === 'function') {
        params.onFailed(searchData, response);
      }
    });
});



// reload so a new csrf token is issued
actions.auth.logout.completed.listen(function(){
  window.setTimeout(function(){
    window.location.replace('', '');
  }, 1);
});

actions.auth.logout.listen(function(){
  dataInterface.logout().done(actions.auth.logout.completed).fail(function(){
    console.error('logout failed for some reason. what should happen now?');
  });
});
actions.auth.verifyLogin.listen(function(){
    dataInterface.selfProfile()
        .done((data/*, msg, req*/)=>{
          if (data.username) {
            actions.auth.verifyLogin.loggedin(data);
          } else {
            actions.auth.verifyLogin.anonymous(data);
          }
        })
        .fail(actions.auth.verifyLogin.failed);
});

actions.auth.changePassword.listen((currentPassword, newPassword) => {
  dataInterface.patchProfile({
    current_password: currentPassword,
    new_password: newPassword
  })
  .done(actions.auth.changePassword.completed)
  .fail(actions.auth.changePassword.failed);
});
actions.auth.changePassword.completed.listen(() => {
  notify(t('changed password successfully'));
});
actions.auth.changePassword.failed.listen(() => {
  notify(t('failed to change password'), 'error');
});

actions.auth.getEnvironment.listen(function(){
  dataInterface.environment()
    .done((data)=>{
      actions.auth.getEnvironment.completed(data);
    })
    .fail(actions.auth.getEnvironment.failed);
});
actions.auth.getEnvironment.failed.listen(() => {
  notify(t('failed to load environment data'), 'error');
});

actions.auth.getApiToken.listen(() => {
  dataInterface.apiToken()
    .done((response) => {
      actions.auth.getApiToken.completed(response.token);
    })
    .fail(actions.auth.getApiToken.failed);
});
actions.auth.getApiToken.failed.listen(() => {
  notify(t('failed to load API token'), 'error');
});

actions.resources.loadAsset.listen(function(params){
  var dispatchMethodName;
  if (params.url) {
    dispatchMethodName = params.url.indexOf('collections') === -1 ?
        'getAsset' : 'getCollection';
  } else {
    dispatchMethodName = {
      c: 'getCollection',
      a: 'getAsset'
    }[params.id[0]];
  }

  dataInterface[dispatchMethodName](params)
    .done(actions.resources.loadAsset.completed)
    .fail(actions.resources.loadAsset.failed);
});

actions.resources.loadAssetContent.listen(function(params){
  dataInterface.getAssetContent(params)
    .done(actions.resources.loadAssetContent.completed)
    .fail(actions.resources.loadAssetContent.failed);
});

actions.resources.listCollections.listen(function(){
  dataInterface.listCollections()
    .done(actions.resources.listCollections.completed)
    .fail(actions.resources.listCollections.failed);
});

actions.resources.updateSubmissionValidationStatus.listen(function(uid, sid, data){
  dataInterface.updateSubmissionValidationStatus(uid, sid, data).done((result) => {
    actions.resources.updateSubmissionValidationStatus.completed(result, sid);
  }).fail((error)=>{
    console.error(error);
    actions.resources.updateSubmissionValidationStatus.failed(error);
  });
});

actions.resources.removeSubmissionValidationStatus.listen((uid, sid) => {
  dataInterface.removeSubmissionValidationStatus(uid, sid).done((result) => {
    actions.resources.removeSubmissionValidationStatus.completed(result, sid);
  }).fail((error)=>{
    console.error(error);
    actions.resources.removeSubmissionValidationStatus.failed(error);
  });
});

actions.hooks.getAll.listen((assetUid, callbacks = {}) => {
  dataInterface.getHooks(assetUid)
    .done((...args) => {
      actions.hooks.getAll.completed(...args);
      if (typeof callbacks.onComplete === 'function') {
        callbacks.onComplete(...args);
      }
    })
    .fail((...args) => {
      actions.hooks.getAll.failed(...args);
      if (typeof callbacks.onFail === 'function') {
        callbacks.onFail(...args);
      }
    });
});

actions.hooks.add.listen((assetUid, data, callbacks = {}) => {
  dataInterface.addExternalService(assetUid, data)
    .done((...args) => {
      actions.hooks.getAll(assetUid);
      actions.hooks.add.completed(...args);
      if (typeof callbacks.onComplete === 'function') {
        callbacks.onComplete(...args);
      }
    })
    .fail((...args) => {
      actions.hooks.add.failed(...args);
      if (typeof callbacks.onFail === 'function') {
        callbacks.onFail(...args);
      }
    });
});
actions.hooks.add.completed.listen((response) => {
  notify(t('REST Service added successfully'));
});
actions.hooks.add.failed.listen((response) => {
  notify(t('Failed adding REST Service'), 'error');
});

actions.hooks.update.listen((assetUid, hookUid, data, callbacks = {}) => {
  dataInterface.updateExternalService(assetUid, hookUid, data)
    .done((...args) => {
      actions.hooks.getAll(assetUid);
      actions.hooks.update.completed(...args);
      if (typeof callbacks.onComplete === 'function') {
        callbacks.onComplete(...args);
      }
    })
    .fail((...args) => {
      actions.hooks.update.failed(...args);
      if (typeof callbacks.onFail === 'function') {
        callbacks.onFail(...args);
      }
    });
});
actions.hooks.update.completed.listen(() => {
  notify(t('REST Service updated successfully'));
});
actions.hooks.update.failed.listen(() => {
  alertify.error(t('Failed saving REST Service'));
});

actions.hooks.delete.listen((assetUid, hookUid, callbacks = {}) => {
  dataInterface.deleteExternalService(assetUid, hookUid)
    .done((...args) => {
      actions.hooks.getAll(assetUid);
      actions.hooks.delete.completed(...args);
      if (typeof callbacks.onComplete === 'function') {
        callbacks.onComplete(...args);
      }
    })
    .fail((...args) => {
      actions.hooks.delete.failed(...args);
      if (typeof callbacks.onFail === 'function') {
        callbacks.onFail(...args);
      }
    });
});
actions.hooks.delete.completed.listen((response) => {
  notify(t('REST Service deleted permanently'));
});
actions.hooks.delete.failed.listen((response) => {
  notify(t('Could not delete REST Service'), 'error');
});

actions.hooks.getLogs.listen((assetUid, hookUid, callbacks = {}) => {
  dataInterface.getHookLogs(assetUid, hookUid)
    .done((...args) => {
      actions.hooks.getLogs.completed(...args);
      if (typeof callbacks.onComplete === 'function') {
        callbacks.onComplete(...args);
      }
    })
    .fail((...args) => {
      actions.hooks.getLogs.failed(...args);
      if (typeof callbacks.onFail === 'function') {
        callbacks.onFail(...args);
      }
    });
});

actions.hooks.retryLog.listen((assetUid, hookUid, lid, callbacks = {}) => {
  dataInterface.retryExternalServiceLog(assetUid, hookUid, lid)
    .done((...args) => {
      actions.hooks.getLogs(assetUid, hookUid);
      actions.hooks.retryLog.completed(...args);
      if (typeof callbacks.onComplete === 'function') {
        callbacks.onComplete(...args);
      }
    })
    .fail((...args) => {
      actions.hooks.retryLog.failed(...args);
      if (typeof callbacks.onFail === 'function') {
        callbacks.onFail(...args);
      }
    });
});
actions.hooks.retryLog.completed.listen((response) => {
  notify(t('Submission retry requested successfully'));
});
actions.hooks.retryLog.failed.listen((response) => {
  notify(t('Submission retry request failed'), 'error');
});

actions.hooks.retryLogs.listen((assetUid, hookUid, callbacks = {}) => {
  dataInterface.retryExternalServiceLogs(assetUid, hookUid)
    .done((...args) => {
      actions.hooks.retryLogs.completed(...args);
      if (typeof callbacks.onComplete === 'function') {
        callbacks.onComplete(...args);
      }
    })
    .fail((...args) => {
      actions.hooks.getLogs(assetUid, hookUid);
      actions.hooks.retryLogs.failed(...args);
      if (typeof callbacks.onFail === 'function') {
        callbacks.onFail(...args);
      }
    });
});
actions.hooks.retryLogs.completed.listen((response) => {
  notify(t(response.detail), 'warning');
});
actions.hooks.retryLogs.failed.listen((response) => {
  notify(t('Retrying all submissions failed'), 'error');
});

module.exports = actions;
