# app.py

from flask import Flask, render_template, request
from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, SubmitField
from wtforms.validators import DataRequired, ValidationError
import phonenumbers
import pycountry

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'



# Get all country codes and full country names
def get_country_codes():
    country_codes = []
    for code, region_codes in phonenumbers.COUNTRY_CODE_TO_REGION_CODE.items():
        if len(region_codes) > 0:
            # Use the first region code to find the country name
            region_code = region_codes[0]
            try:
                country_name = pycountry.countries.get(alpha_2=region_code).name
                country_codes.append((f'+{code}', f'{country_name} (+{code})'))
            except AttributeError:
                # Handle cases where pycountry doesn't have the country
                continue
    # Sort the list by country name for better user experience
    country_codes.sort(key=lambda x: x[1])
    return country_codes



# Custom validator to check if the phone number is valid for the selected country code
def validate_phone_number(form, field):
    try:
        # Construct the full number
        full_number = form.country_code.data + field.data
        # Parse and validate the number
        parsed_number = phonenumbers.parse(full_number, None)
        if not phonenumbers.is_valid_number(parsed_number):
            raise ValidationError('Invalid phone number for the selected country.')
    except phonenumbers.phonenumberutil.NumberParseException:
        raise ValidationError('Invalid phone number format.')


class TelephoneForm(FlaskForm):
    country_code = SelectField('Country Name & Code', choices=get_country_codes(), validators=[DataRequired()])
    phone_number = StringField('Telephone Number', validators=[DataRequired(), validate_phone_number])
    submit = SubmitField('Submit')



@app.route('/', methods=['GET', 'POST'])
def index():
    form = TelephoneForm()
    if form.validate_on_submit():
        country_code = form.country_code.data
        phone_number = form.phone_number.data
        full_number = f'{country_code} {phone_number}'
        return f'Validated and Submitted! Full Telephone Number: {full_number}'
    return render_template('form.html', form=form)


if __name__ == '__main__':
    app.run(debug=True)