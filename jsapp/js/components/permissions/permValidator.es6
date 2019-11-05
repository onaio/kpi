import React from 'react';
import reactMixin from 'react-mixin';
import Reflux from 'reflux';
import autoBind from 'react-autobind';
import permConfig from './permConfig';
import actions from 'js/actions';
import _ from 'underscore';
import {
  t,
  notify,
  replaceSupportEmail
} from 'js/utils';

const INVALID_PERMS_ERROR = t('The stored permissions are invalid. Please assign them again. If this problem persists, contact help@kobotoolbox.org');

class PermValidator extends React.Component {
  constructor(props){
    super(props);
    autoBind(this);
  }

  componentDidMount() {
    this.listenTo(actions.permissions.getAssetPermissions.completed, this.validateBackendData);
  }

  validateBackendData(permissionAssignments) {
    let allImplied = [];
    let allContradictory = [];

    permissionAssignments.forEach((assignment) => {
      const permDef = permConfig.getPermission(assignment.permission);
      allImplied = _.union(allImplied, permDef.implied);
      allContradictory = _.union(allContradictory, permDef.contradictory);
    });

    let hasAllImplied = true;
    allImplied.forEach((implied) => {
      let isFound = false;
      permissionAssignments.forEach((assignment) => {
        if (assignment.permission === implied) {
          isFound = true;
        }
      });
      if (isFound === false) {
        hasAllImplied = false;
      }
    });

    let hasAnyContradictory = false;
    allContradictory.forEach((contradictory) => {
      permissionAssignments.forEach((assignment) => {
        if (assignment.permission === contradictory) {
          hasAnyContradictory = true;
        }
      });
    });

    console.debug('validateBackendData', permissionAssignments, allImplied, allContradictory);

    if (!hasAllImplied || hasAnyContradictory) {
      notify(replaceSupportEmail(INVALID_PERMS_ERROR), 'error');
    }
  }

  render () {
    return null;
  }
}

reactMixin(PermValidator.prototype, Reflux.ListenerMixin);

export default PermValidator;
