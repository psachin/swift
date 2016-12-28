# Copyright (c) 2010-2012 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import mock
import unittest
from abc import ABCMeta
from contextlib import contextmanager
from six import add_metaclass

from swift.common.swob import Request, Response
from swift.common.middleware.acl import (
    parse_acl, format_acl)
from swift.proxy import server as proxy_server
from swift.proxy.controllers.base import headers_to_account_info
from swift.common import constraints
from test.unit import (
    fake_http_connect, FakeRing, FakeMemcache, patch_policies)
from test.unit.proxy import (
    _make_callback_func, save_globals,
    set_http_connect, FakeMemcacheReturnsNone)
from swift.common.storage_policy import StoragePolicy
from swift.common.request_helpers import get_sys_meta_prefix
import swift.proxy.controllers.base
from swift.proxy.controllers.base import get_account_info


@add_metaclass(ABCMeta)
class AccountControllerMeta(object):

    def _make_callback_func(self, context):
        def callback(ipaddr, port, device, partition, method, path,
                     headers=None, query_string=None, ssl=False):
            context['method'] = method
            context['path'] = path
            context['headers'] = headers or {}
        return callback

    def _assert_responses(self, method, test_cases):
        if method in ('PUT', 'DELETE'):
            self.app.allow_account_management = True
        controller = proxy_server.AccountController(self.app, 'AUTH_bob')

        for responses, expected in test_cases:
            with mock.patch(
                    'swift.proxy.controllers.base.http_connect',
                    fake_http_connect(*responses)):
                req = Request.blank('/v1/AUTH_bob')
                resp = getattr(controller, method)(req)

            self.assertEqual(expected,
                             resp.status_int,
                             'Expected %s but got %s. Failed case: %s' %
                             (expected, resp.status_int, str(responses)))

    def assert_status_map(self, method, statuses, expected, env_expected=None,
                          headers=None, **kwargs):
        headers = headers or {}
        with save_globals():
            set_http_connect(*statuses, **kwargs)
            req = Request.blank('/v1/a', {}, headers=headers)
            self.app.update_request(req)
            res = method(req)
            self.assertEqual(res.status_int, expected)
            infocache = res.environ.get('swift.infocache', {})
            if env_expected:
                self.assertEqual(infocache['account/a']['status'],
                                 env_expected)
            set_http_connect(*statuses)
            req = Request.blank('/v1/a/', {})
            self.app.update_request(req)
            res = method(req)
            infocache = res.environ.get('swift.infocache', {})
            self.assertEqual(res.status_int, expected)
            if env_expected:
                self.assertEqual(infocache['account/a']['status'],
                                 env_expected)


@patch_policies([StoragePolicy(0, 'zero', True, object_ring=FakeRing())])
class TestAccountController(AccountControllerMeta, unittest.TestCase):
    def setUp(self):
        self.app = proxy_server.Application(
            None, FakeMemcache(),
            account_ring=FakeRing(), container_ring=FakeRing())

    def test_OPTIONS(self):
        with save_globals():
            self.app.allow_account_management = False
            controller = proxy_server.AccountController(self.app, 'account')
            req = Request.blank('/v1/account', {'REQUEST_METHOD': 'OPTIONS'})
            req.content_length = 0
            resp = controller.OPTIONS(req)
            self.assertEqual(200, resp.status_int)
            for verb in 'OPTIONS GET POST HEAD'.split():
                self.assertIn(verb, resp.headers['Allow'])
            self.assertEqual(len(resp.headers['Allow'].split(', ')), 4)

            # Test a CORS OPTIONS request (i.e. including Origin and
            # Access-Control-Request-Method headers)
            self.app.allow_account_management = False
            controller = proxy_server.AccountController(self.app, 'account')
            req = Request.blank(
                '/v1/account', {'REQUEST_METHOD': 'OPTIONS'},
                headers={'Origin': 'http://foo.com',
                         'Access-Control-Request-Method': 'GET'})
            req.content_length = 0
            resp = controller.OPTIONS(req)
            self.assertEqual(200, resp.status_int)
            for verb in 'OPTIONS GET POST HEAD'.split():
                self.assertIn(verb, resp.headers['Allow'])
            self.assertEqual(len(resp.headers['Allow'].split(', ')), 4)

            self.app.allow_account_management = True
            controller = proxy_server.AccountController(self.app, 'account')
            req = Request.blank('/v1/account', {'REQUEST_METHOD': 'OPTIONS'})
            req.content_length = 0
            resp = controller.OPTIONS(req)
            self.assertEqual(200, resp.status_int)
            for verb in 'OPTIONS GET POST PUT DELETE HEAD'.split():
                self.assertIn(verb, resp.headers['Allow'])
            self.assertEqual(len(resp.headers['Allow'].split(', ')), 6)

    def test_GET(self):
        with save_globals():
            controller = proxy_server.AccountController(self.app, 'a')
            # GET returns after the first successful call to an Account Server
            self.assert_status_map(controller.GET, (200,), 200, 200)
            self.assert_status_map(controller.GET, (503, 200), 200, 200)
            self.assert_status_map(controller.GET, (503, 503, 200), 200, 200)
            self.assert_status_map(controller.GET, (204,), 204, 204)
            self.assert_status_map(controller.GET, (503, 204), 204, 204)
            self.assert_status_map(controller.GET, (503, 503, 204), 204, 204)
            self.assert_status_map(controller.GET, (404, 200), 200, 200)
            self.assert_status_map(controller.GET, (404, 404, 200), 200, 200)
            self.assert_status_map(controller.GET, (404, 503, 204), 204, 204)
            # If Account servers fail, if autocreate = False, return majority
            # response
            self.assert_status_map(controller.GET, (404, 404, 404), 404, 404)
            self.assert_status_map(controller.GET, (404, 404, 503), 404, 404)
            self.assert_status_map(controller.GET, (404, 503, 503), 503)

            self.app.memcache = FakeMemcacheReturnsNone()
            self.assert_status_map(controller.GET, (404, 404, 404), 404, 404)

    def test_GET_autocreate(self):
        with save_globals():
            controller = proxy_server.AccountController(self.app, 'a')
            self.app.memcache = FakeMemcacheReturnsNone()
            self.assertFalse(self.app.account_autocreate)
            # Repeat the test for autocreate = False and 404 by all
            self.assert_status_map(controller.GET,
                                   (404, 404, 404), 404)
            self.assert_status_map(controller.GET,
                                   (404, 503, 404), 404)
            # When autocreate is True, if none of the nodes respond 2xx
            # And quorum of the nodes responded 404,
            # ALL nodes are asked to create the account
            # If successful, the GET request is repeated.
            controller.app.account_autocreate = True
            self.assert_status_map(controller.GET,
                                   (404, 404, 404), 204)
            self.assert_status_map(controller.GET,
                                   (404, 503, 404), 204)

            # We always return 503 if no majority between 4xx, 3xx or 2xx found
            self.assert_status_map(controller.GET,
                                   (500, 500, 400), 503)

    def test_HEAD(self):
        # Same behaviour as GET
        with save_globals():
            controller = proxy_server.AccountController(self.app, 'a')
            self.assert_status_map(controller.HEAD, (200,), 200, 200)
            self.assert_status_map(controller.HEAD, (503, 200), 200, 200)
            self.assert_status_map(controller.HEAD, (503, 503, 200), 200, 200)
            self.assert_status_map(controller.HEAD, (204,), 204, 204)
            self.assert_status_map(controller.HEAD, (503, 204), 204, 204)
            self.assert_status_map(controller.HEAD, (204, 503, 503), 204, 204)
            self.assert_status_map(controller.HEAD, (204,), 204, 204)
            self.assert_status_map(controller.HEAD, (404, 404, 404), 404, 404)
            self.assert_status_map(controller.HEAD, (404, 404, 200), 200, 200)
            self.assert_status_map(controller.HEAD, (404, 200), 200, 200)
            self.assert_status_map(controller.HEAD, (404, 404, 503), 404, 404)
            self.assert_status_map(controller.HEAD, (404, 503, 503), 503)
            self.assert_status_map(controller.HEAD, (404, 503, 204), 204, 204)

    def test_HEAD_autocreate(self):
        # Same behaviour as GET
        with save_globals():
            controller = proxy_server.AccountController(self.app, 'a')
            self.app.memcache = FakeMemcacheReturnsNone()
            self.assertFalse(self.app.account_autocreate)
            self.assert_status_map(controller.HEAD,
                                   (404, 404, 404), 404)
            controller.app.account_autocreate = True
            self.assert_status_map(controller.HEAD,
                                   (404, 404, 404), 204)
            self.assert_status_map(controller.HEAD,
                                   (500, 404, 404), 204)
            # We always return 503 if no majority between 4xx, 3xx or 2xx found
            self.assert_status_map(controller.HEAD,
                                   (500, 500, 400), 503)

    def test_POST_autocreate(self):
        with save_globals():
            controller = proxy_server.AccountController(self.app, 'a')
            self.app.memcache = FakeMemcacheReturnsNone()
            # first test with autocreate being False
            self.assertFalse(self.app.account_autocreate)
            self.assert_status_map(controller.POST,
                                   (404, 404, 404), 404)
            # next turn it on and test account being created than updated
            controller.app.account_autocreate = True
            self.assert_status_map(
                controller.POST,
                (404, 404, 404, 202, 202, 202, 201, 201, 201), 201)
            # account_info  PUT account  POST account
            self.assert_status_map(
                controller.POST,
                (404, 404, 503, 201, 201, 503, 204, 204, 504), 204)
            # what if create fails
            self.assert_status_map(
                controller.POST,
                (404, 404, 404, 403, 403, 403, 400, 400, 400), 400)

    def test_POST_autocreate_with_sysmeta(self):
        with save_globals():
            controller = proxy_server.AccountController(self.app, 'a')
            self.app.memcache = FakeMemcacheReturnsNone()
            # first test with autocreate being False
            self.assertFalse(self.app.account_autocreate)
            self.assert_status_map(controller.POST,
                                   (404, 404, 404), 404)
            # next turn it on and test account being created than updated
            controller.app.account_autocreate = True
            calls = []
            callback = _make_callback_func(calls)
            key, value = 'X-Account-Sysmeta-Blah', 'something'
            headers = {key: value}
            self.assert_status_map(
                controller.POST,
                (404, 404, 404, 202, 202, 202, 201, 201, 201), 201,
                #  POST       , autocreate PUT, POST again
                headers=headers,
                give_connect=callback)
            self.assertEqual(9, len(calls))
            for call in calls:
                self.assertIn(key, call['headers'],
                              '%s call, key %s missing in headers %s' %
                              (call['method'], key, call['headers']))
                self.assertEqual(value, call['headers'][key])

    def test_connection_refused(self):
        self.app.account_ring.get_nodes('account')
        for dev in self.app.account_ring.devs:
            dev['ip'] = '127.0.0.1'
            dev['port'] = 1  # can't connect on this port
        controller = proxy_server.AccountController(self.app, 'account')
        req = Request.blank('/v1/account', environ={'REQUEST_METHOD': 'HEAD'})
        self.app.update_request(req)
        resp = controller.HEAD(req)
        self.assertEqual(resp.status_int, 503)

    def test_other_socket_error(self):
        self.app.account_ring.get_nodes('account')
        for dev in self.app.account_ring.devs:
            dev['ip'] = '127.0.0.1'
            dev['port'] = -1  # invalid port number
        controller = proxy_server.AccountController(self.app, 'account')
        req = Request.blank('/v1/account', environ={'REQUEST_METHOD': 'HEAD'})
        self.app.update_request(req)
        resp = controller.HEAD(req)
        self.assertEqual(resp.status_int, 503)

    def test_response_get_accept_ranges_header(self):
        with save_globals():
            set_http_connect(200, 200, body='{}')
            controller = proxy_server.AccountController(self.app, 'account')
            req = Request.blank('/v1/a?format=json')
            self.app.update_request(req)
            res = controller.GET(req)
            self.assertIn('accept-ranges', res.headers)
            self.assertEqual(res.headers['accept-ranges'], 'bytes')

    def test_response_head_accept_ranges_header(self):
        with save_globals():
            set_http_connect(200, 200, body='{}')
            controller = proxy_server.AccountController(self.app, 'account')
            req = Request.blank('/v1/a?format=json')
            self.app.update_request(req)
            res = controller.HEAD(req)
            res.body
            self.assertIn('accept-ranges', res.headers)
            self.assertEqual(res.headers['accept-ranges'], 'bytes')

    def test_PUT(self):
        with save_globals():
            controller = proxy_server.AccountController(self.app, 'account')

            def test_status_map(statuses, expected, **kwargs):
                set_http_connect(*statuses, **kwargs)
                self.app.memcache.store = {}
                req = Request.blank('/v1/a', {})
                req.content_length = 0
                self.app.update_request(req)
                res = controller.PUT(req)
                expected = str(expected)
                self.assertEqual(res.status[:len(expected)], expected)
            test_status_map((201, 201, 201), 405)
            self.app.allow_account_management = True
            test_status_map((201, 201, 201), 201)
            test_status_map((201, 201, 500), 201)
            test_status_map((201, 500, 500), 503)
            test_status_map((204, 500, 404), 503)

    def test_PUT_max_account_name_length(self):
        with save_globals():
            self.app.allow_account_management = True
            limit = constraints.MAX_ACCOUNT_NAME_LENGTH
            controller = proxy_server.AccountController(self.app, '1' * limit)
            self.assert_status_map(controller.PUT, (201, 201, 201), 201)
            controller = proxy_server.AccountController(
                self.app, '2' * (limit + 1))
            self.assert_status_map(controller.PUT, (201, 201, 201), 400)

    def test_PUT_connect_exceptions(self):
        with save_globals():
            self.app.allow_account_management = True
            controller = proxy_server.AccountController(self.app, 'account')
            self.assert_status_map(controller.PUT, (201, 201, -1), 201)
            self.assert_status_map(controller.PUT, (201, -1, -1), 503)
            self.assert_status_map(controller.PUT, (503, 503, -1), 503)

    def test_PUT_status(self):
        with save_globals():
            self.app.allow_account_management = True
            controller = proxy_server.AccountController(self.app, 'account')
            self.assert_status_map(controller.PUT, (201, 201, 202), 202)

    def metadata_helper(self, method):
        for test_header, test_value in (
                ('X-Account-Meta-TestHeader', 'TestValue'),
                ('X-Account-Meta-TestHeader', ''),
                ('X-Remove-Account-Meta-TestHeader', 'anything')):
            test_errors = []

            def test_connect(ipaddr, port, device, partition, method, path,
                             headers=None, query_string=None):
                if path == '/a':
                    find_header = test_header
                    find_value = test_value
                    if find_header.lower().startswith('x-remove-'):
                        find_header = \
                            find_header.lower().replace('-remove', '', 1)
                        find_value = ''
                    for k, v in headers.items():
                        if k.lower() == find_header.lower() and \
                                v == find_value:
                            break
                    else:
                        test_errors.append('%s: %s not in %s' %
                                           (find_header, find_value, headers))
            with save_globals():
                self.app.allow_account_management = True
                controller = \
                    proxy_server.AccountController(self.app, 'a')
                set_http_connect(201, 201, 201, give_connect=test_connect)
                req = Request.blank('/v1/a/c',
                                    environ={'REQUEST_METHOD': method},
                                    headers={test_header: test_value})
                self.app.update_request(req)
                getattr(controller, method)(req)
                self.assertEqual(test_errors, [])

    def test_PUT_metadata(self):
        self.metadata_helper('PUT')

    def test_POST_metadata(self):
        self.metadata_helper('POST')

    def bad_metadata_helper(self, method):
        with save_globals():
            self.app.allow_account_management = True
            controller = proxy_server.AccountController(self.app, 'a')
            set_http_connect(200, 201, 201, 201)
            req = Request.blank('/v1/a/c', environ={'REQUEST_METHOD': method})
            self.app.update_request(req)
            resp = getattr(controller, method)(req)
            self.assertEqual(resp.status_int, 201)

            set_http_connect(201, 201, 201)
            req = Request.blank('/v1/a/c', environ={'REQUEST_METHOD': method},
                                headers={'X-Account-Meta-' +
                                ('a' * constraints.MAX_META_NAME_LENGTH): 'v'})
            self.app.update_request(req)
            resp = getattr(controller, method)(req)
            self.assertEqual(resp.status_int, 201)
            set_http_connect(201, 201, 201)
            req = Request.blank(
                '/v1/a/c', environ={'REQUEST_METHOD': method},
                headers={'X-Account-Meta-' +
                         ('a' * (constraints.MAX_META_NAME_LENGTH + 1)): 'v'})
            self.app.update_request(req)
            resp = getattr(controller, method)(req)
            self.assertEqual(resp.status_int, 400)

            set_http_connect(201, 201, 201)
            req = Request.blank('/v1/a/c', environ={'REQUEST_METHOD': method},
                                headers={'X-Account-Meta-Too-Long':
                                'a' * constraints.MAX_META_VALUE_LENGTH})
            self.app.update_request(req)
            resp = getattr(controller, method)(req)
            self.assertEqual(resp.status_int, 201)
            set_http_connect(201, 201, 201)
            req = Request.blank('/v1/a/c', environ={'REQUEST_METHOD': method},
                                headers={'X-Account-Meta-Too-Long':
                                'a' * (constraints.MAX_META_VALUE_LENGTH + 1)})
            self.app.update_request(req)
            resp = getattr(controller, method)(req)
            self.assertEqual(resp.status_int, 400)

            set_http_connect(201, 201, 201)
            headers = {}
            for x in range(constraints.MAX_META_COUNT):
                headers['X-Account-Meta-%d' % x] = 'v'
            req = Request.blank('/v1/a/c', environ={'REQUEST_METHOD': method},
                                headers=headers)
            self.app.update_request(req)
            resp = getattr(controller, method)(req)
            self.assertEqual(resp.status_int, 201)
            set_http_connect(201, 201, 201)
            headers = {}
            for x in range(constraints.MAX_META_COUNT + 1):
                headers['X-Account-Meta-%d' % x] = 'v'
            req = Request.blank('/v1/a/c', environ={'REQUEST_METHOD': method},
                                headers=headers)
            self.app.update_request(req)
            resp = getattr(controller, method)(req)
            self.assertEqual(resp.status_int, 400)

            set_http_connect(201, 201, 201)
            headers = {}
            header_value = 'a' * constraints.MAX_META_VALUE_LENGTH
            size = 0
            x = 0
            while size < (constraints.MAX_META_OVERALL_SIZE - 4
                          - constraints.MAX_META_VALUE_LENGTH):
                size += 4 + constraints.MAX_META_VALUE_LENGTH
                headers['X-Account-Meta-%04d' % x] = header_value
                x += 1
            if constraints.MAX_META_OVERALL_SIZE - size > 1:
                headers['X-Account-Meta-a'] = \
                    'a' * (constraints.MAX_META_OVERALL_SIZE - size - 1)
            req = Request.blank('/v1/a/c', environ={'REQUEST_METHOD': method},
                                headers=headers)
            self.app.update_request(req)
            resp = getattr(controller, method)(req)
            self.assertEqual(resp.status_int, 201)
            set_http_connect(201, 201, 201)
            headers['X-Account-Meta-a'] = \
                'a' * (constraints.MAX_META_OVERALL_SIZE - size)
            req = Request.blank('/v1/a/c', environ={'REQUEST_METHOD': method},
                                headers=headers)
            self.app.update_request(req)
            resp = getattr(controller, method)(req)
            self.assertEqual(resp.status_int, 400)

    def test_PUT_bad_metadata(self):
        self.bad_metadata_helper('PUT')

    def test_POST_bad_metadata(self):
        self.bad_metadata_helper('POST')

    def test_DELETE(self):
        with save_globals():
            controller = proxy_server.AccountController(self.app, 'account')

            def test_status_map(statuses, expected, **kwargs):
                set_http_connect(*statuses, **kwargs)
                self.app.memcache.store = {}
                req = Request.blank('/v1/a', {'REQUEST_METHOD': 'DELETE'})
                req.content_length = 0
                self.app.update_request(req)
                res = controller.DELETE(req)
                expected = str(expected)
                self.assertEqual(res.status[:len(expected)], expected)
            test_status_map((201, 201, 201), 405)
            self.app.allow_account_management = True
            test_status_map((201, 201, 201), 201)
            test_status_map((201, 201, 500), 201)
            test_status_map((201, 500, 500), 503)
            test_status_map((204, 500, 404), 503)

    def test_DELETE_with_query_string(self):
        # Extra safety in case someone typos a query string for an
        # account-level DELETE request that was really meant to be caught by
        # some middleware.
        with save_globals():
            controller = proxy_server.AccountController(self.app, 'account')

            def test_status_map(statuses, expected, **kwargs):
                set_http_connect(*statuses, **kwargs)
                self.app.memcache.store = {}
                req = Request.blank('/v1/a?whoops',
                                    environ={'REQUEST_METHOD': 'DELETE'})
                req.content_length = 0
                self.app.update_request(req)
                res = controller.DELETE(req)
                expected = str(expected)
                self.assertEqual(res.status[:len(expected)], expected)
            test_status_map((201, 201, 201), 400)
            self.app.allow_account_management = True
            test_status_map((201, 201, 201), 400)
            test_status_map((201, 201, 500), 400)
            test_status_map((201, 500, 500), 400)
            test_status_map((204, 500, 404), 400)

    # Original functions start from here
    def test_account_info_in_response_env(self):
        controller = proxy_server.AccountController(self.app, 'AUTH_bob')
        with mock.patch('swift.proxy.controllers.base.http_connect',
                        fake_http_connect(200, body='')):
            req = Request.blank('/v1/AUTH_bob', {'PATH_INFO': '/v1/AUTH_bob'})
            resp = controller.HEAD(req)
        self.assertEqual(2, resp.status_int // 100)
        self.assertIn('account/AUTH_bob', resp.environ['swift.infocache'])
        self.assertEqual(
            headers_to_account_info(resp.headers),
            resp.environ['swift.infocache']['account/AUTH_bob'])

    def test_swift_owner(self):
        owner_headers = {
            'x-account-meta-temp-url-key': 'value',
            'x-account-meta-temp-url-key-2': 'value'}
        controller = proxy_server.AccountController(self.app, 'a')

        req = Request.blank('/v1/a')
        with mock.patch('swift.proxy.controllers.base.http_connect',
                        fake_http_connect(200, headers=owner_headers)):
            resp = controller.HEAD(req)
        self.assertEqual(2, resp.status_int // 100)
        for key in owner_headers:
            self.assertNotIn(key, resp.headers)

        req = Request.blank('/v1/a', environ={'swift_owner': True})
        with mock.patch('swift.proxy.controllers.base.http_connect',
                        fake_http_connect(200, headers=owner_headers)):
            resp = controller.HEAD(req)
        self.assertEqual(2, resp.status_int // 100)
        for key in owner_headers:
            self.assertIn(key, resp.headers)

    def test_get_deleted_account(self):
        resp_headers = {
            'x-account-status': 'deleted',
        }
        controller = proxy_server.AccountController(self.app, 'a')

        req = Request.blank('/v1/a')
        with mock.patch('swift.proxy.controllers.base.http_connect',
                        fake_http_connect(404, headers=resp_headers)):
            resp = controller.HEAD(req)
        self.assertEqual(410, resp.status_int)

    def test_long_acct_names(self):
        long_acct_name = '%sLongAccountName' % (
            'Very' * (constraints.MAX_ACCOUNT_NAME_LENGTH // 4))
        controller = proxy_server.AccountController(self.app, long_acct_name)

        req = Request.blank('/v1/%s' % long_acct_name)
        with mock.patch('swift.proxy.controllers.base.http_connect',
                        fake_http_connect(200)):
            resp = controller.HEAD(req)
        self.assertEqual(400, resp.status_int)

        with mock.patch('swift.proxy.controllers.base.http_connect',
                        fake_http_connect(200)):
            resp = controller.GET(req)
        self.assertEqual(400, resp.status_int)

        with mock.patch('swift.proxy.controllers.base.http_connect',
                        fake_http_connect(200)):
            resp = controller.POST(req)
        self.assertEqual(400, resp.status_int)

    def test_sys_meta_headers_PUT(self):
        # check that headers in sys meta namespace make it through
        # the proxy controller
        sys_meta_key = '%stest' % get_sys_meta_prefix('account')
        sys_meta_key = sys_meta_key.title()
        user_meta_key = 'X-Account-Meta-Test'
        # allow PUTs to account...
        self.app.allow_account_management = True
        controller = proxy_server.AccountController(self.app, 'a')
        context = {}
        callback = self._make_callback_func(context)
        hdrs_in = {sys_meta_key: 'foo',
                   user_meta_key: 'bar',
                   'x-timestamp': '1.0'}
        req = Request.blank('/v1/a', headers=hdrs_in)
        with mock.patch('swift.proxy.controllers.base.http_connect',
                        fake_http_connect(200, 200, give_connect=callback)):
            controller.PUT(req)
        self.assertEqual(context['method'], 'PUT')
        self.assertIn(sys_meta_key, context['headers'])
        self.assertEqual(context['headers'][sys_meta_key], 'foo')
        self.assertIn(user_meta_key, context['headers'])
        self.assertEqual(context['headers'][user_meta_key], 'bar')
        self.assertNotEqual(context['headers']['x-timestamp'], '1.0')

    def test_sys_meta_headers_POST(self):
        # check that headers in sys meta namespace make it through
        # the proxy controller
        sys_meta_key = '%stest' % get_sys_meta_prefix('account')
        sys_meta_key = sys_meta_key.title()
        user_meta_key = 'X-Account-Meta-Test'
        controller = proxy_server.AccountController(self.app, 'a')
        context = {}
        callback = self._make_callback_func(context)
        hdrs_in = {sys_meta_key: 'foo',
                   user_meta_key: 'bar',
                   'x-timestamp': '1.0'}
        req = Request.blank('/v1/a', headers=hdrs_in)
        with mock.patch('swift.proxy.controllers.base.http_connect',
                        fake_http_connect(200, 200, give_connect=callback)):
            controller.POST(req)
        self.assertEqual(context['method'], 'POST')
        self.assertIn(sys_meta_key, context['headers'])
        self.assertEqual(context['headers'][sys_meta_key], 'foo')
        self.assertIn(user_meta_key, context['headers'])
        self.assertEqual(context['headers'][user_meta_key], 'bar')
        self.assertNotEqual(context['headers']['x-timestamp'], '1.0')

    def _make_user_and_sys_acl_headers_data(self):
        acl = {
            'admin': ['AUTH_alice', 'AUTH_bob'],
            'read-write': ['AUTH_carol'],
            'read-only': [],
        }
        user_prefix = 'x-account-'  # external, user-facing
        user_headers = {(user_prefix + 'access-control'): format_acl(
            version=2, acl_dict=acl)}
        sys_prefix = get_sys_meta_prefix('account')   # internal, system-facing
        sys_headers = {(sys_prefix + 'core-access-control'): format_acl(
            version=2, acl_dict=acl)}
        return user_headers, sys_headers

    def test_account_acl_headers_translated_for_GET_HEAD(self):
        # Verify that a GET/HEAD which receives X-Account-Sysmeta-Acl-* headers
        # from the account server will remap those headers to X-Account-Acl-*

        hdrs_ext, hdrs_int = self._make_user_and_sys_acl_headers_data()
        controller = proxy_server.AccountController(self.app, 'acct')

        for verb in ('GET', 'HEAD'):
            req = Request.blank('/v1/acct', environ={'swift_owner': True})
            controller.GETorHEAD_base = lambda *_: Response(
                headers=hdrs_int, environ={
                    'PATH_INFO': '/acct',
                    'REQUEST_METHOD': verb,
                })
            method = getattr(controller, verb)
            resp = method(req)
            for header, value in hdrs_ext.items():
                if value:
                    self.assertEqual(resp.headers.get(header), value)
                else:
                    # blank ACLs should result in no header
                    self.assertNotIn(header, resp.headers)

    def test_add_acls_impossible_cases(self):
        # For test coverage: verify that defensive coding does defend, in cases
        # that shouldn't arise naturally

        # add_acls should do nothing if REQUEST_METHOD isn't HEAD/GET/PUT/POST
        resp = Response()
        controller = proxy_server.AccountController(self.app, 'a')
        resp.environ['PATH_INFO'] = '/a'
        resp.environ['REQUEST_METHOD'] = 'OPTIONS'
        controller.add_acls_from_sys_metadata(resp)
        self.assertEqual(1, len(resp.headers))  # we always get Content-Type
        self.assertEqual(2, len(resp.environ))

    def test_cache_key_impossible_cases(self):
        # For test coverage: verify that defensive coding does defend, in cases
        # that shouldn't arise naturally
        with self.assertRaises(ValueError):
            # Container needs account
            swift.proxy.controllers.base.get_cache_key(None, 'c')

        with self.assertRaises(ValueError):
            # Object needs account
            swift.proxy.controllers.base.get_cache_key(None, 'c', 'o')

        with self.assertRaises(ValueError):
            # Object needs container
            swift.proxy.controllers.base.get_cache_key('a', None, 'o')

    def test_stripping_swift_admin_headers(self):
        # Verify that a GET/HEAD which receives privileged headers from the
        # account server will strip those headers for non-swift_owners

        headers = {
            'x-account-meta-harmless': 'hi mom',
            'x-account-meta-temp-url-key': 's3kr1t',
        }
        controller = proxy_server.AccountController(self.app, 'acct')

        for verb in ('GET', 'HEAD'):
            for env in ({'swift_owner': True}, {'swift_owner': False}):
                req = Request.blank('/v1/acct', environ=env)
                controller.GETorHEAD_base = lambda *_: Response(
                    headers=headers, environ={
                        'PATH_INFO': '/acct',
                        'REQUEST_METHOD': verb,
                    })
                method = getattr(controller, verb)
                resp = method(req)
                self.assertEqual(resp.headers.get('x-account-meta-harmless'),
                                 'hi mom')
                privileged_header_present = (
                    'x-account-meta-temp-url-key' in resp.headers)
                self.assertEqual(privileged_header_present, env['swift_owner'])

    def test_response_code_for_PUT(self):
        PUT_TEST_CASES = [
            ((201, 201, 201), 201),
            ((201, 201, 404), 201),
            ((201, 201, 503), 201),
            ((201, 404, 404), 404),
            ((201, 404, 503), 503),
            ((201, 503, 503), 503),
            ((404, 404, 404), 404),
            ((404, 404, 503), 404),
            ((404, 503, 503), 503),
            ((503, 503, 503), 503)
        ]
        self._assert_responses('PUT', PUT_TEST_CASES)

    def test_response_code_for_DELETE(self):
        DELETE_TEST_CASES = [
            ((204, 204, 204), 204),
            ((204, 204, 404), 204),
            ((204, 204, 503), 204),
            ((204, 404, 404), 404),
            ((204, 404, 503), 503),
            ((204, 503, 503), 503),
            ((404, 404, 404), 404),
            ((404, 404, 503), 404),
            ((404, 503, 503), 503),
            ((503, 503, 503), 503)
        ]
        self._assert_responses('DELETE', DELETE_TEST_CASES)

    def test_response_code_for_POST(self):
        POST_TEST_CASES = [
            ((204, 204, 204), 204),
            ((204, 204, 404), 204),
            ((204, 204, 503), 204),
            ((204, 404, 404), 404),
            ((204, 404, 503), 503),
            ((204, 503, 503), 503),
            ((404, 404, 404), 404),
            ((404, 404, 503), 404),
            ((404, 503, 503), 503),
            ((503, 503, 503), 503)
        ]
        self._assert_responses('POST', POST_TEST_CASES)


@patch_policies(
    [StoragePolicy(0, 'zero', True, object_ring=FakeRing(replicas=4))])
class TestAccountController4Replicas(AccountControllerMeta, unittest.TestCase):
    def setUp(self):
        self.app = proxy_server.Application(
            None,
            FakeMemcache(),
            account_ring=FakeRing(replicas=4),
            container_ring=FakeRing(replicas=4))

    def test_response_code_for_PUT(self):
        PUT_TEST_CASES = [
            ((201, 201, 201, 201), 201),
            ((201, 201, 201, 404), 201),
            ((201, 201, 201, 503), 201),
            ((201, 201, 404, 404), 201),
            ((201, 201, 404, 503), 201),
            ((201, 201, 503, 503), 201),
            ((201, 404, 404, 404), 404),
            ((201, 404, 404, 503), 404),
            ((201, 404, 503, 503), 503),
            ((201, 503, 503, 503), 503),
            ((404, 404, 404, 404), 404),
            ((404, 404, 404, 503), 404),
            ((404, 404, 503, 503), 404),
            ((404, 503, 503, 503), 503),
            ((503, 503, 503, 503), 503)
        ]
        self._assert_responses('PUT', PUT_TEST_CASES)

    def test_response_code_for_DELETE(self):
        DELETE_TEST_CASES = [
            ((204, 204, 204, 204), 204),
            ((204, 204, 204, 404), 204),
            ((204, 204, 204, 503), 204),
            ((204, 204, 404, 404), 204),
            ((204, 204, 404, 503), 204),
            ((204, 204, 503, 503), 204),
            ((204, 404, 404, 404), 404),
            ((204, 404, 404, 503), 404),
            ((204, 404, 503, 503), 503),
            ((204, 503, 503, 503), 503),
            ((404, 404, 404, 404), 404),
            ((404, 404, 404, 503), 404),
            ((404, 404, 503, 503), 404),
            ((404, 503, 503, 503), 503),
            ((503, 503, 503, 503), 503)
        ]
        self._assert_responses('DELETE', DELETE_TEST_CASES)

    def test_response_code_for_POST(self):
        POST_TEST_CASES = [
            ((204, 204, 204, 204), 204),
            ((204, 204, 204, 404), 204),
            ((204, 204, 204, 503), 204),
            ((204, 204, 404, 404), 204),
            ((204, 204, 404, 503), 204),
            ((204, 204, 503, 503), 204),
            ((204, 404, 404, 404), 404),
            ((204, 404, 404, 503), 404),
            ((204, 404, 503, 503), 503),
            ((204, 503, 503, 503), 503),
            ((404, 404, 404, 404), 404),
            ((404, 404, 404, 503), 404),
            ((404, 404, 503, 503), 404),
            ((404, 503, 503, 503), 503),
            ((503, 503, 503, 503), 503)
        ]
        self._assert_responses('POST', POST_TEST_CASES)


@patch_policies([StoragePolicy(0, 'zero', True, object_ring=FakeRing())])
class TestGetAccountInfo(unittest.TestCase):
    def setUp(self):
        self.app = proxy_server.Application(
            None, FakeMemcache(),
            account_ring=FakeRing(), container_ring=FakeRing())

    def test_get_deleted_account_410(self):
        resp_headers = {'x-account-status': 'deleted'}

        req = Request.blank('/v1/a')
        with mock.patch('swift.proxy.controllers.base.http_connect',
                        fake_http_connect(404, headers=resp_headers)):
            info = get_account_info(req.environ, self.app)
        self.assertEqual(410, info.get('status'))


@patch_policies([StoragePolicy(0, 'zero', True, object_ring=FakeRing())])
class TestAccountControllerFakeGetResponse(unittest.TestCase):
    """
    Test all the faked-out GET responses for accounts that don't exist. They
    have to match the responses for empty accounts that really exist.
    """
    def setUp(self):
        conf = {'account_autocreate': 'yes'}
        self.app = proxy_server.Application(conf, FakeMemcache(),
                                            account_ring=FakeRing(),
                                            container_ring=FakeRing())
        self.app.memcache = FakeMemcacheReturnsNone()

    def test_GET_autocreate_accept_json(self):
        with save_globals():
            set_http_connect(*([404] * 100))  # nonexistent: all backends 404
            req = Request.blank(
                '/v1/a', headers={'Accept': 'application/json'},
                environ={'REQUEST_METHOD': 'GET',
                         'PATH_INFO': '/v1/a'})
            resp = req.get_response(self.app)
            self.assertEqual(200, resp.status_int)
            self.assertEqual('application/json; charset=utf-8',
                             resp.headers['Content-Type'])
            self.assertEqual("[]", resp.body)

    def test_GET_autocreate_format_json(self):
        with save_globals():
            set_http_connect(*([404] * 100))  # nonexistent: all backends 404
            req = Request.blank('/v1/a?format=json',
                                environ={'REQUEST_METHOD': 'GET',
                                         'PATH_INFO': '/v1/a',
                                         'QUERY_STRING': 'format=json'})
            resp = req.get_response(self.app)
            self.assertEqual(200, resp.status_int)
            self.assertEqual('application/json; charset=utf-8',
                             resp.headers['Content-Type'])
            self.assertEqual("[]", resp.body)

    def test_GET_autocreate_accept_xml(self):
        with save_globals():
            set_http_connect(*([404] * 100))  # nonexistent: all backends 404
            req = Request.blank('/v1/a', headers={"Accept": "text/xml"},
                                environ={'REQUEST_METHOD': 'GET',
                                         'PATH_INFO': '/v1/a'})

            resp = req.get_response(self.app)
            self.assertEqual(200, resp.status_int)

            self.assertEqual('text/xml; charset=utf-8',
                             resp.headers['Content-Type'])
            empty_xml_listing = ('<?xml version="1.0" encoding="UTF-8"?>\n'
                                 '<account name="a">\n</account>')
            self.assertEqual(empty_xml_listing, resp.body)

    def test_GET_autocreate_format_xml(self):
        with save_globals():
            set_http_connect(*([404] * 100))  # nonexistent: all backends 404
            req = Request.blank('/v1/a?format=xml',
                                environ={'REQUEST_METHOD': 'GET',
                                         'PATH_INFO': '/v1/a',
                                         'QUERY_STRING': 'format=xml'})
            resp = req.get_response(self.app)
            self.assertEqual(200, resp.status_int)
            self.assertEqual('application/xml; charset=utf-8',
                             resp.headers['Content-Type'])
            empty_xml_listing = ('<?xml version="1.0" encoding="UTF-8"?>\n'
                                 '<account name="a">\n</account>')
            self.assertEqual(empty_xml_listing, resp.body)

    def test_GET_autocreate_accept_unknown(self):
        with save_globals():
            set_http_connect(*([404] * 100))  # nonexistent: all backends 404
            req = Request.blank('/v1/a', headers={"Accept": "mystery/meat"},
                                environ={'REQUEST_METHOD': 'GET',
                                         'PATH_INFO': '/v1/a'})
            resp = req.get_response(self.app)
            self.assertEqual(406, resp.status_int)

    def test_GET_autocreate_format_invalid_utf8(self):
        with save_globals():
            set_http_connect(*([404] * 100))  # nonexistent: all backends 404
            req = Request.blank('/v1/a?format=\xff\xfe',
                                environ={'REQUEST_METHOD': 'GET',
                                         'PATH_INFO': '/v1/a',
                                         'QUERY_STRING': 'format=\xff\xfe'})
            resp = req.get_response(self.app)
            self.assertEqual(400, resp.status_int)

    def test_account_acl_header_access(self):
        acl = {
            'admin': ['AUTH_alice'],
            'read-write': ['AUTH_bob'],
            'read-only': ['AUTH_carol'],
        }
        prefix = get_sys_meta_prefix('account')
        privileged_headers = {(prefix + 'core-access-control'): format_acl(
            version=2, acl_dict=acl)}

        app = proxy_server.Application(
            None, FakeMemcache(), account_ring=FakeRing(),
            container_ring=FakeRing())

        with save_globals():
            # Mock account server will provide privileged information (ACLs)
            set_http_connect(200, 200, 200, headers=privileged_headers)
            req = Request.blank('/v1/a', environ={'REQUEST_METHOD': 'GET'})
            resp = app.handle_request(req)

            # Not a swift_owner -- ACLs should NOT be in response
            header = 'X-Account-Access-Control'
            self.assertNotIn(header, resp.headers, '%r was in %r' % (
                header, resp.headers))

            # Same setup -- mock acct server will provide ACLs
            set_http_connect(200, 200, 200, headers=privileged_headers)
            req = Request.blank('/v1/a', environ={'REQUEST_METHOD': 'GET',
                                                  'swift_owner': True})
            resp = app.handle_request(req)

            # For a swift_owner, the ACLs *should* be in response
            self.assertIn(header, resp.headers, '%r not in %r' % (
                header, resp.headers))

    def test_account_acls_through_delegation(self):

        # Define a way to grab the requests sent out from the AccountController
        # to the Account Server, and a way to inject responses we'd like the
        # Account Server to return.
        resps_to_send = []

        @contextmanager
        def patch_account_controller_method(verb):
            old_method = getattr(proxy_server.AccountController, verb)
            new_method = lambda self, req, *_, **__: resps_to_send.pop(0)
            try:
                setattr(proxy_server.AccountController, verb, new_method)
                yield
            finally:
                setattr(proxy_server.AccountController, verb, old_method)

        def make_test_request(http_method, swift_owner=True):
            env = {
                'REQUEST_METHOD': http_method,
                'swift_owner': swift_owner,
            }
            acl = {
                'admin': ['foo'],
                'read-write': ['bar'],
                'read-only': ['bas'],
            }
            headers = {} if http_method in ('GET', 'HEAD') else {
                'x-account-access-control': format_acl(version=2, acl_dict=acl)
            }

            return Request.blank('/v1/a', environ=env, headers=headers)

        # Our AccountController will invoke methods to communicate with the
        # Account Server, and they will return responses like these:
        def make_canned_response(http_method):
            acl = {
                'admin': ['foo'],
                'read-write': ['bar'],
                'read-only': ['bas'],
            }
            headers = {'x-account-sysmeta-core-access-control': format_acl(
                version=2, acl_dict=acl)}
            canned_resp = Response(headers=headers)
            canned_resp.environ = {
                'PATH_INFO': '/acct',
                'REQUEST_METHOD': http_method,
            }
            resps_to_send.append(canned_resp)

        app = proxy_server.Application(
            None, FakeMemcache(), account_ring=FakeRing(),
            container_ring=FakeRing())
        app.allow_account_management = True

        ext_header = 'x-account-access-control'
        with patch_account_controller_method('GETorHEAD_base'):
            # GET/HEAD requests should remap sysmeta headers from acct server
            for verb in ('GET', 'HEAD'):
                make_canned_response(verb)
                req = make_test_request(verb)
                resp = app.handle_request(req)
                h = parse_acl(version=2, data=resp.headers.get(ext_header))
                self.assertEqual(h['admin'], ['foo'])
                self.assertEqual(h['read-write'], ['bar'])
                self.assertEqual(h['read-only'], ['bas'])

                # swift_owner = False: GET/HEAD shouldn't return sensitive info
                make_canned_response(verb)
                req = make_test_request(verb, swift_owner=False)
                resp = app.handle_request(req)
                h = resp.headers
                self.assertIsNone(h.get(ext_header))

                # swift_owner unset: GET/HEAD shouldn't return sensitive info
                make_canned_response(verb)
                req = make_test_request(verb, swift_owner=False)
                del req.environ['swift_owner']
                resp = app.handle_request(req)
                h = resp.headers
                self.assertIsNone(h.get(ext_header))

        # Verify that PUT/POST requests remap sysmeta headers from acct server
        with patch_account_controller_method('make_requests'):
            make_canned_response('PUT')
            req = make_test_request('PUT')
            resp = app.handle_request(req)

            h = parse_acl(version=2, data=resp.headers.get(ext_header))
            self.assertEqual(h['admin'], ['foo'])
            self.assertEqual(h['read-write'], ['bar'])
            self.assertEqual(h['read-only'], ['bas'])

            make_canned_response('POST')
            req = make_test_request('POST')
            resp = app.handle_request(req)

            h = parse_acl(version=2, data=resp.headers.get(ext_header))
            self.assertEqual(h['admin'], ['foo'])
            self.assertEqual(h['read-write'], ['bar'])
            self.assertEqual(h['read-only'], ['bas'])

if __name__ == '__main__':
    unittest.main()
