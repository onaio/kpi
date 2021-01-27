/**
 * For displaying your secret API token
 */

import React from 'react';
import autoBind from 'react-autobind';
import {bem} from 'js/bem';
import {actions} from 'js/actions';
import {t} from 'js/utils';

class ApiTokenDisplay extends React.Component {
  constructor(props) {
    super(props);
    this.HIDDEN_VAL = '*'.repeat(40);
    this.state = {
      token: this.HIDDEN_VAL,
      isLoadingToken: false
    };
    this.unlisteners = [];
    autoBind(this);
  }

  componentDidMount() {
    this.unlisteners.push(
      actions.auth.getApiToken.completed.listen(this.onGetApiTokenCompleted.bind(this)),
      actions.auth.getApiToken.failed.listen(this.onGetApiTokenFailed.bind(this))
    );
  }

  componentWillUnmount() {
    this.unlisteners.forEach((clb) => {clb();});
  }

  onGetApiTokenCompleted(token) {
    this.setState({
      token: token,
      isLoadingToken: false
    });
  }

  onGetApiTokenFailed() {
    this.setState({isLoadingToken: false});
  }

  toggleApiTokenVisibility() {
    this.setState({isTokenVisible: !this.state.isTokenVisible});
    actions.auth.getApiToken();
  }

  onInputFocus(evt) {
    evt.currentTarget.select();
  }

  render() {
    return (
      <bem.FormModal__item m='api-token'>
        <label>{t('API token')}</label>

        <input
          type={this.state.isTokenVisible && !this.state.isLoadingToken ? 'text' : 'password'}
          value={this.state.token}
          onFocus={this.onInputFocus}
          readOnly
        />

        <button
          onClick={this.toggleApiTokenVisibility}
          disabled={this.state.isLoadingToken}
          className='mdl-button mdl-button--icon'
        >
          <i className={this.state.isTokenVisible ? 'k-icon k-icon-view-no'
                                                  : 'k-icon k-icon-view'}
          />
        </button>
      </bem.FormModal__item>
    );
  }
}

export default ApiTokenDisplay;
