/**
 * A text box generic component.
 *
 * Properties:
 * - type <string>: one of AVAILABLE_TYPES, defaults to DEFAULT_TYPE
 * - value <string>: required
 * - onChange <function>: required
 * - errors <string[]> or <string> or <boolean>: for visual error indication and displaying error messages
 * - label <string>
 * - placeholder <string>
 * - description <string>
 *
 * TODO: would be best to move it to `jsapp/js/components/generic` directory.
 */

import React from 'react';
import autoBind from 'react-autobind';
import TextareaAutosize from 'react-autosize-textarea';
import bem from '../bem';

/*
Properties:
- type <string>: one of AVAILABLE_TYPES, defaults to DEFAULT_TYPE
- value <string>: required
- onChange <function>: required
- onBlur <function>
- onKeyPress <function>
- errors <string[]> or <string>
- label <string>
- placeholder <string>
- description <string>
*/
class TextBox extends React.Component {
  constructor(props){
    super(props);
    this.AVAILABLE_TYPES = [
      'text-multiline',
      'text',
      'email',
      'password',
      'url'
    ];
    this.DEFAULT_TYPE = 'text';
    autoBind(this);
  }

  onChange(evt) {
    this.props.onChange(evt.currentTarget.value);
  }

  onBlur(evt) {
    if (typeof this.props.onBlur === 'function') {
      this.props.onBlur(evt.currentTarget.value);
    }
  }

  onKeyPress(evt) {
    if (typeof this.props.onKeyPress === 'function') {
      this.props.onKeyPress(evt.key, evt);
    }
  }

  render() {
    let modifiers = [];

    let errors = [];
    if (Array.isArray(this.props.errors)) {
      errors = this.props.errors;
    } else if (typeof this.props.errors === 'string' && this.props.errors.length > 0) {
      errors.push(this.props.errors);
    }
    if (errors.length > 0 || this.props.errors === true) {
      modifiers.push('error');
    }

    let type = this.DEFAULT_TYPE;
    if (this.props.type && this.AVAILABLE_TYPES.indexOf(this.props.type) !== -1) {
      type = this.props.type;
    } else if (this.props.type) {
      throw new Error(`Unknown TextBox type: ${this.props.type}!`);
    }

    const inputProps = {
      value: this.props.value,
      placeholder: this.props.placeholder,
      onChange: this.onChange,
      onBlur: this.onBlur,
      onKeyPress: this.onKeyPress
    };

    return (
      <bem.TextBox m={modifiers}>
        {this.props.label &&
          <bem.TextBox__label>
            {this.props.label}
          </bem.TextBox__label>
        }

        {this.props.type === 'text-multiline' &&
          <TextareaAutosize
            className='text-box__input'
            {...inputProps}
          />
        }
        {this.props.type !== 'text-multiline' &&
          <bem.TextBox__input
            type={type}
            {...inputProps}
          />
        }

        {this.props.description &&
          <bem.TextBox__description>
            {this.props.description}
          </bem.TextBox__description>
        }

        {errors.length > 0 &&
          <bem.TextBox__error>
            {errors.join('\n')}
          </bem.TextBox__error>
        }
      </bem.TextBox>
    );
  }
}

export default TextBox;
