import React from 'react';
import autoBind from 'react-autobind';
import Checkbox from 'js/components/checkbox';
import TextBox from 'js/components/textBox';
import {
  assign,
  t
} from 'js/utils';
import {
  META_QUESTION_TYPES,
} from 'js/constants';
import {bem} from 'js/bem';

const AUDIT_HELP_URL = 'http://support.kobotoolbox.org/en/articles/2648050-audit-logging-meta-question-type';

/**
 * @prop {object} survey
 * @prop {function} onChange
 */
export default class MetadataEditor extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      metaProperties: []
    };
    autoBind(this);
  }

  componentDidMount() {
    this.rebuildState();
  }

  rebuildState() {
    const newState = {
      metaProperties: []
    };
    META_QUESTION_TYPES.forEach((metaType) => {
      const detail = this.getSurveyDetail(metaType);
      if (detail) {
        newState.metaProperties.push(assign({}, detail.attributes));
      }
    });
    this.setState(newState);
  }

  getMetaProperty(metaType) {
    return this.state.metaProperties.find((metaProp) => {
      return metaProp.name === metaType;
    });
  }

  getSurveyDetail(sdId) {
    return this.props.survey.surveyDetails.filter((sd) => {
      return sd.attributes.name === sdId;
    })[0];
  }

  onCheckboxChange(name, isChecked) {
    this.getSurveyDetail(name).set('value', isChecked);
    this.rebuildState();
    if (typeof this.props.onChange === 'function') {
      this.props.onChange();
    }
  }

  onAuditParametersChange(newVal) {
    this.getSurveyDetail(META_QUESTION_TYPES.get('audit')).set('parameters', newVal);
    this.rebuildState();
    if (typeof this.props.onChange === 'function') {
      this.props.onChange();
    }
  }

  isAuditEnabled() {
    const metaProp = this.getMetaProperty(META_QUESTION_TYPES.get('audit'));
    return metaProp.value === true;
  }

  getAuditParameters() {
    const metaProp = this.getMetaProperty(META_QUESTION_TYPES.get('audit'));
    return metaProp.parameters;
  }

  renderAuditInputLabel() {
    return (
      <React.Fragment>
        {t('Audit settings')}
        <bem.TextBox__labelLink
          href={AUDIT_HELP_URL}
          target='_blank'
        >
          <i className='k-icon k-icon-help'/>
        </bem.TextBox__labelLink>
      </React.Fragment>
    );
  }

  render() {
    if (this.state.metaProperties.length === 0) {
      return null;
    }

    const leftColumn = [
      META_QUESTION_TYPES.get('start'),
      META_QUESTION_TYPES.get('end'),
      META_QUESTION_TYPES.get('today'),
      META_QUESTION_TYPES.get('deviceid'),
      META_QUESTION_TYPES.get('audit')
    ];
    const rightColumn = [
      META_QUESTION_TYPES.get('username'),
      META_QUESTION_TYPES.get('simserial'),
      META_QUESTION_TYPES.get('subscriberid'),
      META_QUESTION_TYPES.get('phonenumber')
    ];

    return (
      <bem.FormBuilderMeta>
        <bem.FormBuilderMeta__columns>
          <bem.FormBuilderMeta__column>
            {leftColumn.map((metaType) => {
              const metaProp = this.getMetaProperty(metaType);
              return (
                <Checkbox
                  key={`meta-${metaProp.name}`}
                  label={metaProp.label}
                  checked={metaProp.value}
                  onChange={this.onCheckboxChange.bind(this, metaProp.name)}
                />
              );
            })}
          </bem.FormBuilderMeta__column>

          <bem.FormBuilderMeta__column>
            {rightColumn.map((metaType) => {
              const metaProp = this.getMetaProperty(metaType);
              return (
                <Checkbox
                  key={`meta-${metaProp.name}`}
                  label={metaProp.label}
                  checked={metaProp.value}
                  onChange={this.onCheckboxChange.bind(this, metaProp.name)}
                />
              );
            })}
          </bem.FormBuilderMeta__column>
        </bem.FormBuilderMeta__columns>

        {this.isAuditEnabled() &&
          <bem.FormBuilderMeta__row>
            <TextBox
              label={this.renderAuditInputLabel()}
              value={this.getAuditParameters()}
              onChange={this.onAuditParametersChange}
            />
          </bem.FormBuilderMeta__row>
        }

      </bem.FormBuilderMeta>
    );
  }
}
