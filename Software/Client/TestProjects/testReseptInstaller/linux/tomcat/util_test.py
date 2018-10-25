#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import unittest
import os

sys.path.insert(0, '/usr/local/bin/keytalk')
import util


class TestUtil(unittest.TestCase):

    def test_run_cmd_with_success(self):
        self.assertEquals(util.run_cmd('pwd'), os.getcwd())

    def test_run_cmd_with_error(self):
        self.assertRaises(Exception, util.run_cmd, 'nonexistent_command')

    def test_strip_json_comments(self):
        json_with_comments = '''
        [
        # number one
        'first',
        // number two
        2,
        "three"
        ]
        '''
        expected_json = '''
        [

        'first',

        2,
        "three"
        ]
        '''
        self.assertEquals(util.strip_json_comments(json_with_comments), expected_json)

    def test_get_cert_validity_percentage_with_success(self):
        self.assertEqual(util.get_cert_validity_percentage(
                         "DemoProvider", "CUST_PASSWD_INTERNAL"), 10)

    def test_get_cert_validity_percentage_with_error(self):
        self.assertRaises(
            Exception,
            util.get_cert_validity_percentage,
            "DemoProvider",
            "invalid-service")
        self.assertRaises(
            Exception,
            util.get_cert_validity_percentage,
            "invalid-provider",
            "CUST_PASSWD_INTERNAL")

    def test_get_keytalk_providers(self):
        self.assertEqual(util.get_keytalk_providers(), ['DemoProvider'])

    def test_get_keytalk_services(self):
        demo_provider_services = ["CUST_PASSWD_INTERNAL",
                                  "CUST_CR_MYSQL",
                                  "CUST_ANO_INTERNAL_TESTUI",
                                  ]
        self.assertEqual(
            sorted(
                util.get_keytalk_services('DemoProvider')),
            sorted(demo_provider_services))

    def test_censor_string(self):
        self.assertEqual(
            util.censor_string(
                'Some secret text with lots of secrets',
                ['secret']),
            'Some <erased> text with lots of <erased>s')
        self.assertEqual(util.censor_string('Some secret text with lots of hidden secrets', [
                         'secret', 'hidden']), 'Some <erased> text with lots of <erased> <erased>s')
        self.assertEqual(
            util.censor_string(
                'Some !@#$%^&*()\\/ text with lots of !@#$%^&*()\\/s',
                ['!@#$%^&*()\\/']),
            'Some <erased> text with lots of <erased>s')

    def test_populate_defaults(self):
        # given
        known_settings = {'Host': {'required': True,
                                    'dependencies': []},

                           'ServerName': {'required': False,
                                          'dependencies': []},

                           'KeystoreLocation': {'required': False,
                                                'dependencies': []},

                           'KeystorePassword': {'required': False,
                                                'dependencies': []}}

        # whens/thens
        settings_dict = util.populate_defaults({}, known_settings)
        self.assertEquals(settings_dict, {'Host': None,
                                          'ServerName': None,
                                          'KeystoreLocation': None,
                                          'KeystorePassword': None})

    def test_validate_setting_dependencies(self):
        # given
        known_settings = {'Required': {'required': True,
                                       'dependencies': []},

                          'Optional': {'required': False,
                                       'dependencies': []},

                          'RequiredWithDependency': {'required': True,
                                                     'dependencies': ['Optional']},

                          'OptionalWithDependency': {'required': False,
                                                     'dependencies': ['Optional']}}
        # whens/thens
        errors = util.validate_setting_dependencies(
            {
                'Required': 'value',
                'Optional': 'value2',
                'RequiredWithDependency': 'value3',
                'OptionalWithDependency': 'value4'},
            known_settings)
        self.assertEqual(errors, [])

        errors = util.validate_setting_dependencies({'Required': 'value'}, known_settings)
        self.assertEqual(errors, [])

        errors = util.validate_setting_dependencies(
            {'Required': 'value', 'Optional': 'value2', 'RequiredWithDependency': 'value3'}, known_settings)
        self.assertEqual(errors, [])

        errors = util.validate_setting_dependencies({}, known_settings)
        self.assertEqual(errors, ['Required setting "Required" not found.'])

        errors = util.validate_setting_dependencies(
            {'Required': 'value', 'Optional': 'value2'}, known_settings)
        self.assertEqual(
            errors,
            ['The current configuration requires setting "RequiredWithDependency".'])

    def test_parse_settings(self):
        known_settings = {
            'Required': {
                'required': True,
                'dependencies': [],
                'default_value': 'not_used_since_required'},
            'Optional': {
                'required': False,
                'dependencies': [],
                'default_value': 'optional_default'},
            'RequiredWithDependency': {
                'required': True,
                'dependencies': ['Optional'],
                'default_value': 'not_used_since_required'},
            'OptionalWithDependency': {
                'required': False,
                'dependencies': ['Optional']},
            'OptionalWithDependency2': {
                'required': False,
                'dependencies': ['OptionalWithDependency'],
                'default_value': 'optional_with_dependency_2_default'}}

        # whens/thens
        settings, errors = util.parse_settings({'Required': 'value', 'Optional': 'value2', 'RequiredWithDependency': 'value3',
                                                'OptionalWithDependency': 'value4', 'OptionalWithDependency2': 'value5'}, known_settings)
        self.assertEqual(errors, [])
        self.assertEquals(settings, {'Required': 'value',
                                     'Optional': 'value2',
                                     'RequiredWithDependency': 'value3',
                                     'OptionalWithDependency': 'value4',
                                     'OptionalWithDependency2': 'value5'})

        settings, errors = util.parse_settings({'Required': 'value'}, known_settings)
        self.assertEqual(errors, [])
        self.assertEquals(settings, {'Required': 'value',
                                     'Optional': 'optional_default',
                                     'RequiredWithDependency': None,
                                     'OptionalWithDependency': None,
                                     'OptionalWithDependency2': None})

        settings, errors = util.parse_settings(
            {'Required': 'value', 'Optional': 'value2', 'RequiredWithDependency': 'value3'}, known_settings)
        self.assertEqual(errors, [])
        self.assertEquals(settings, {'Required': 'value',
                                     'Optional': 'value2',
                                     'RequiredWithDependency': 'value3',
                                     'OptionalWithDependency': None,
                                     'OptionalWithDependency2': None})

        settings, errors = util.parse_settings(
            {'Required': 'value', 'Optional': 'value2', 'RequiredWithDependency': 'value3', 'OptionalWithDependency': 'value4'}, known_settings)
        self.assertEqual(errors, [])
        self.assertEquals(settings,
                          {'Required': 'value',
                           'Optional': 'value2',
                           'RequiredWithDependency': 'value3',
                           'OptionalWithDependency': 'value4',
                           'OptionalWithDependency2': 'optional_with_dependency_2_default'})

        settings, errors = util.parse_settings({}, known_settings)
        self.assertEqual(errors, ['Required setting "Required" not found.'])
        self.assertEquals(settings, None)

        settings, errors = util.parse_settings(
            {'Required': 'value', 'Optional': 'value2'}, known_settings)
        self.assertEqual(
            errors,
            ['The current configuration requires setting "RequiredWithDependency".'])
        self.assertEquals(settings, None)

        settings, errors = util.parse_settings(
            {'Required': 'value', 'Optional': 'value2', 'RequiredWithDependency': 'value3',
             'OptionalWithDependency': 'value4', 'OptionalWithDependency2': 'value5', 'UnknownSetting': 'value6'}, known_settings)
        self.assertEqual(len(errors), 1)
        self.assertRegexpMatches(errors[0], 'Unknown setting "UnknownSetting" encountered')
        self.assertEquals(settings, None)



if __name__ == '__main__':
    unittest.main()
