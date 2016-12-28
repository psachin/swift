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
from eventlet import Timeout
import random
import re
from contextlib import contextmanager
from six import add_metaclass
import time

from swift.common import constraints
from swift.common.swob import Request
from swift.proxy import server as proxy_server
import swift.proxy.controllers
from swift.proxy.controllers import base as proxy_base
from swift.proxy.controllers.base import (
    cors_validation, headers_to_container_info)
from test.unit import fake_http_connect, FakeRing, FakeMemcache
from swift.common.exceptions import ChunkReadTimeout
from swift.common.request_helpers import get_sys_meta_prefix
from swift.common.storage_policy import StoragePolicy, POLICIES
from swift.common.swob import (
    HTTPException, HTTPUnauthorized, Response)

from test.unit import (
    patch_policies, mocked_http_conn, debug_logger)
from test.unit.common.ring.test_ring import TestRingBase
from test.unit.proxy import (
    _make_callback_func, save_globals,
    set_http_connect, FakeMemcacheReturnsNone)
from test.unit.proxy.test_server import (
    node_error_count, node_last_error,
    set_node_errors, sortHeaderNames)


@add_metaclass(ABCMeta)
class ContainerControllerMeta(object):

    CONTAINER_REPLICAS = 3

    def setUp(self):
        TestRingBase.setUp(self)
        self.container_ring = FakeRing(
            replicas=self.CONTAINER_REPLICAS,
            max_more_nodes=9)
        self.app = proxy_server.Application(
            None, FakeMemcache(),
            account_ring=FakeRing(),
            container_ring=self.container_ring,
            logger=debug_logger())

        self.account_info = {
            'status': 200,
            'container_count': '10',
            'total_object_count': '100',
            'bytes': '1000',
            'meta': {},
            'sysmeta': {},
        }

        class FakeAccountInfoContainerController(
                proxy_server.ContainerController):

            def account_info(controller, *args, **kwargs):
                patch_path = 'swift.proxy.controllers.base.get_account_info'
                with mock.patch(patch_path) as mock_get_info:
                    mock_get_info.return_value = dict(self.account_info)
                    return super(FakeAccountInfoContainerController,
                                 controller).account_info(
                                     *args, **kwargs)
        _orig_get_controller = self.app.get_controller

        def wrapped_get_controller(*args, **kwargs):
            with mock.patch('swift.proxy.server.ContainerController',
                            new=FakeAccountInfoContainerController):
                return _orig_get_controller(*args, **kwargs)
        self.app.get_controller = wrapped_get_controller

    def _make_callback_func(self, context):
        def callback(ipaddr, port, device, partition, method, path,
                     headers=None, query_string=None, ssl=False):
            context['method'] = method
            context['path'] = path
            context['headers'] = headers or {}
        return callback

    def _assert_responses(self, method, test_cases):
        controller = proxy_server.ContainerController(self.app, 'a', 'c')

        for responses, expected in test_cases:
            with mock.patch(
                    'swift.proxy.controllers.base.http_connect',
                    fake_http_connect(*responses)):
                req = Request.blank('/v1/a/c')
                resp = getattr(controller, method)(req)

            self.assertEqual(expected,
                             resp.status_int,
                             'Expected %s but got %s. Failed case: %s' %
                             (expected, resp.status_int, str(responses)))


@patch_policies([StoragePolicy(0, 'zero', True, object_ring=FakeRing())])
class TestContainerController(ContainerControllerMeta, TestRingBase):

    def test_container_info_got_cached(self):
        controller = proxy_server.ContainerController(self.app, 'a', 'c')
        with mock.patch('swift.proxy.controllers.base.http_connect',
                        fake_http_connect(200, 200, body='')):
            req = Request.blank('/v1/a/c', {'PATH_INFO': '/v1/a/c'})
            resp = controller.HEAD(req)
        self.assertEqual(2, resp.status_int // 100)
        # Make sure it's in both swift.infocache and memcache
        self.assertIn("container/a/c", resp.environ['swift.infocache'])
        self.assertEqual(
            headers_to_container_info(resp.headers),
            resp.environ['swift.infocache']['container/a/c'])
        from_memcache = self.app.memcache.get('container/a/c')
        self.assertTrue(from_memcache)

    def test_swift_owner(self):
        owner_headers = {
            'x-container-read': 'value', 'x-container-write': 'value',
            'x-container-sync-key': 'value', 'x-container-sync-to': 'value'}
        controller = proxy_server.ContainerController(self.app, 'a', 'c')

        req = Request.blank('/v1/a/c')
        with mock.patch('swift.proxy.controllers.base.http_connect',
                        fake_http_connect(200, 200, headers=owner_headers)):
            resp = controller.HEAD(req)
        self.assertEqual(2, resp.status_int // 100)
        for key in owner_headers:
            self.assertNotIn(key, resp.headers)

        req = Request.blank('/v1/a/c', environ={'swift_owner': True})
        with mock.patch('swift.proxy.controllers.base.http_connect',
                        fake_http_connect(200, 200, headers=owner_headers)):
            resp = controller.HEAD(req)
        self.assertEqual(2, resp.status_int // 100)
        for key in owner_headers:
            self.assertIn(key, resp.headers)

    def test_sys_meta_headers_PUT(self):
        # check that headers in sys meta namespace make it through
        # the container controller
        sys_meta_key = '%stest' % get_sys_meta_prefix('container')
        sys_meta_key = sys_meta_key.title()
        user_meta_key = 'X-Container-Meta-Test'
        controller = proxy_server.ContainerController(self.app, 'a', 'c')

        context = {}
        callback = self._make_callback_func(context)
        hdrs_in = {sys_meta_key: 'foo',
                   user_meta_key: 'bar',
                   'x-timestamp': '1.0'}
        req = Request.blank('/v1/a/c', headers=hdrs_in)
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
        # the container controller
        sys_meta_key = '%stest' % get_sys_meta_prefix('container')
        sys_meta_key = sys_meta_key.title()
        user_meta_key = 'X-Container-Meta-Test'
        controller = proxy_server.ContainerController(self.app, 'a', 'c')
        context = {}
        callback = self._make_callback_func(context)
        hdrs_in = {sys_meta_key: 'foo',
                   user_meta_key: 'bar',
                   'x-timestamp': '1.0'}
        req = Request.blank('/v1/a/c', headers=hdrs_in)
        with mock.patch('swift.proxy.controllers.base.http_connect',
                        fake_http_connect(200, 200, give_connect=callback)):
            controller.POST(req)
        self.assertEqual(context['method'], 'POST')
        self.assertIn(sys_meta_key, context['headers'])
        self.assertEqual(context['headers'][sys_meta_key], 'foo')
        self.assertIn(user_meta_key, context['headers'])
        self.assertEqual(context['headers'][user_meta_key], 'bar')
        self.assertNotEqual(context['headers']['x-timestamp'], '1.0')

    def test_node_errors(self):
        self.app.sort_nodes = lambda n: n

        for method in ('PUT', 'DELETE', 'POST'):
            def test_status_map(statuses, expected):
                self.app._error_limiting = {}
                req = Request.blank('/v1/a/c', method=method)
                with mocked_http_conn(*statuses) as fake_conn:
                    resp = req.get_response(self.app)
                self.assertEqual(resp.status_int, expected)
                for req in fake_conn.requests:
                    self.assertEqual(req['method'], method)
                    self.assertTrue(req['path'].endswith('/a/c'))

            base_status = [201] * 3
            # test happy path
            test_status_map(list(base_status), 201)
            for i in range(3):
                self.assertEqual(node_error_count(
                    self.app, self.container_ring.devs[i]), 0)
            # single node errors and test isolation
            for i in range(3):
                status_list = list(base_status)
                status_list[i] = 503
                status_list.append(201)
                test_status_map(status_list, 201)
                for j in range(3):
                    expected = 1 if j == i else 0
                    self.assertEqual(node_error_count(
                        self.app, self.container_ring.devs[j]), expected)
            # timeout
            test_status_map((201, Timeout(), 201, 201), 201)
            self.assertEqual(node_error_count(
                self.app, self.container_ring.devs[1]), 1)

            # exception
            test_status_map((Exception('kaboom!'), 201, 201, 201), 201)
            self.assertEqual(node_error_count(
                self.app, self.container_ring.devs[0]), 1)

            # insufficient storage
            test_status_map((201, 201, 507, 201), 201)
            self.assertEqual(node_error_count(
                self.app, self.container_ring.devs[2]),
                self.app.error_suppression_limit + 1)

    def test_response_codes_for_GET(self):
        nodes = self.app.container_ring.replicas
        handoffs = self.app.request_node_count(nodes) - nodes
        GET_TEST_CASES = [
            ([], 503),
            ([200], 200),
            ([404, 200], 200),
            ([404] * nodes + [200], 200),
            ([Timeout()] * nodes + [404] * handoffs, 404),
            ([Timeout()] * (nodes + handoffs), 503),
            ([Timeout()] * (nodes + handoffs - 1) + [404], 404),
            ([503, 200], 200),
            ([507, 200], 200),
        ]
        failures = []
        for case, expected in GET_TEST_CASES:
            try:
                with mocked_http_conn(*case):
                    req = Request.blank('/v1/a/c')
                    resp = req.get_response(self.app)
                    try:
                        self.assertEqual(resp.status_int, expected)
                    except AssertionError:
                        msg = '%r => %s (expected %s)' % (
                            case, resp.status_int, expected)
                        failures.append(msg)
            except AssertionError as e:
                # left over status failure
                msg = '%r => %s' % (case, e)
                failures.append(msg)
        if failures:
            self.fail('Some requests did not have expected response:\n' +
                      '\n'.join(failures))

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


@patch_policies([
    StoragePolicy(0, 'zero', True, object_ring=FakeRing(base_port=3000)),
    StoragePolicy(1, 'one', False, object_ring=FakeRing(base_port=3000)),
    StoragePolicy(2, 'two', False, True, object_ring=FakeRing(base_port=3000))
])
class TestContainerControllerBasePort(unittest.TestCase):
    def setUp(self):
        self.app = proxy_server.Application(
            None, FakeMemcache(),
            account_ring=FakeRing(),
            container_ring=FakeRing(base_port=2000),
            logger=debug_logger())

    def test_convert_policy_to_index(self):
        controller = swift.proxy.controllers.ContainerController(self.app,
                                                                 'a', 'c')
        expected = {
            'zero': 0,
            'ZeRo': 0,
            'one': 1,
            'OnE': 1,
        }
        for name, index in expected.items():
            req = Request.blank('/a/c', headers={'Content-Length': '0',
                                                 'Content-Type': 'text/plain',
                                                 'X-Storage-Policy': name})
            self.assertEqual(controller._convert_policy_to_index(req), index)
        # default test
        req = Request.blank('/a/c', headers={'Content-Length': '0',
                                             'Content-Type': 'text/plain'})
        self.assertIsNone(controller._convert_policy_to_index(req))
        # negative test
        req = Request.blank('/a/c',
                            headers={'Content-Length': '0',
                                     'Content-Type': 'text/plain',
                                     'X-Storage-Policy': 'nada'})
        self.assertRaises(HTTPException, controller._convert_policy_to_index,
                          req)
        # storage policy two is deprecated
        req = Request.blank('/a/c', headers={'Content-Length': '0',
                                             'Content-Type': 'text/plain',
                                             'X-Storage-Policy': 'two'})
        self.assertRaises(HTTPException, controller._convert_policy_to_index,
                          req)

    def test_convert_index_to_name(self):
        policy = random.choice(list(POLICIES))
        req = Request.blank('/v1/a/c')
        with mocked_http_conn(
                200, 200,
                headers={'X-Backend-Storage-Policy-Index': int(policy)},
        ) as fake_conn:
            resp = req.get_response(self.app)
            self.assertRaises(StopIteration, fake_conn.code_iter.next)
        self.assertEqual(resp.status_int, 200)
        self.assertEqual(resp.headers['X-Storage-Policy'], policy.name)

    def test_no_convert_index_to_name_when_container_not_found(self):
        policy = random.choice(list(POLICIES))
        req = Request.blank('/v1/a/c')
        with mocked_http_conn(
                200, 404, 404, 404,
                headers={'X-Backend-Storage-Policy-Index':
                         int(policy)}) as fake_conn:
            resp = req.get_response(self.app)
            self.assertRaises(StopIteration, fake_conn.code_iter.next)
        self.assertEqual(resp.status_int, 404)
        self.assertIsNone(resp.headers['X-Storage-Policy'])

    def test_error_convert_index_to_name(self):
        req = Request.blank('/v1/a/c')
        with mocked_http_conn(
                200, 200,
                headers={'X-Backend-Storage-Policy-Index': '-1'}) as fake_conn:
            resp = req.get_response(self.app)
            self.assertRaises(StopIteration, fake_conn.code_iter.next)
        self.assertEqual(resp.status_int, 200)
        self.assertIsNone(resp.headers['X-Storage-Policy'])
        error_lines = self.app.logger.get_lines_for_level('error')
        self.assertEqual(2, len(error_lines))
        for msg in error_lines:
            expected = "Could not translate " \
                "X-Backend-Storage-Policy-Index ('-1')"
            self.assertIn(expected, msg)

    def test_transfer_headers(self):
        src_headers = {'x-remove-versions-location': 'x',
                       'x-container-read': '*:user',
                       'x-remove-container-sync-key': 'x'}
        dst_headers = {'x-versions-location': 'backup'}
        controller = swift.proxy.controllers.ContainerController(self.app,
                                                                 'a', 'c')
        controller.transfer_headers(src_headers, dst_headers)
        expected_headers = {'x-versions-location': '',
                            'x-container-read': '*:user',
                            'x-container-sync-key': ''}
        self.assertEqual(dst_headers, expected_headers)

    def assert_status_map(self, method, statuses, expected,
                          raise_exc=False, missing_container=False):
        with save_globals():
            kwargs = {}
            if raise_exc:
                kwargs['raise_exc'] = raise_exc
            kwargs['missing_container'] = missing_container
            set_http_connect(*statuses, **kwargs)
            self.app.memcache.store = {}
            req = Request.blank('/v1/a/c', headers={'Content-Length': '0',
                                'Content-Type': 'text/plain'})
            self.app.update_request(req)
            res = method(req)
            self.assertEqual(res.status_int, expected)
            set_http_connect(*statuses, **kwargs)
            self.app.memcache.store = {}
            req = Request.blank('/v1/a/c/', headers={'Content-Length': '0',
                                'Content-Type': 'text/plain'})
            self.app.update_request(req)
            res = method(req)
            self.assertEqual(res.status_int, expected)

    def test_HEAD_GET(self):
        with save_globals():
            controller = proxy_server.ContainerController(self.app, 'a', 'c')

            def test_status_map(statuses, expected,
                                c_expected=None, a_expected=None, **kwargs):
                set_http_connect(*statuses, **kwargs)
                self.app.memcache.store = {}
                req = Request.blank('/v1/a/c', {})
                self.app.update_request(req)
                res = controller.HEAD(req)
                self.assertEqual(res.status[:len(str(expected))],
                                 str(expected))
                infocache = res.environ.get('swift.infocache', {})
                if expected < 400:
                    self.assertIn('x-works', res.headers)
                    self.assertEqual(res.headers['x-works'], 'yes')
                if expected < 300:
                    self.assertIn('last-modified', res.headers)
                    self.assertEqual(res.headers['last-modified'], '1')
                if c_expected:
                    self.assertIn('container/a/c', infocache)
                    self.assertEqual(
                        infocache['container/a/c']['status'],
                        c_expected)
                else:
                    self.assertNotIn('container/a/c', infocache)
                if a_expected:
                    self.assertIn('account/a', infocache)
                    self.assertEqual(infocache['account/a']['status'],
                                     a_expected)
                else:
                    self.assertNotIn('account/a', res.environ)

                set_http_connect(*statuses, **kwargs)
                self.app.memcache.store = {}
                req = Request.blank('/v1/a/c', {})
                self.app.update_request(req)
                res = controller.GET(req)
                self.assertEqual(res.status[:len(str(expected))],
                                 str(expected))
                infocache = res.environ.get('swift.infocache', {})
                if expected < 400:
                    self.assertIn('x-works', res.headers)
                    self.assertEqual(res.headers['x-works'], 'yes')
                if expected < 300:
                    self.assertIn('last-modified', res.headers)
                    self.assertEqual(res.headers['last-modified'], '1')
                if c_expected:
                    self.assertIn('container/a/c', infocache)
                    self.assertEqual(
                        infocache['container/a/c']['status'],
                        c_expected)
                else:
                    self.assertNotIn('container/a/c', infocache)
                if a_expected:
                    self.assertIn('account/a', infocache)
                    self.assertEqual(infocache['account/a']['status'],
                                     a_expected)
                else:
                    self.assertNotIn('account/a', infocache)
            # In all the following tests cache 200 for account
            # return and cache vary for container
            # return 200 and cache 200 for account and container
            test_status_map((200, 200, 404, 404), 200, 200, 200)
            test_status_map((200, 200, 500, 404), 200, 200, 200)
            # return 304 don't cache container
            test_status_map((200, 304, 500, 404), 304, None, 200)
            # return 404 and cache 404 for container
            test_status_map((200, 404, 404, 404), 404, 404, 200)
            test_status_map((200, 404, 404, 500), 404, 404, 200)
            # return 503, don't cache container
            test_status_map((200, 500, 500, 500), 503, None, 200)
            self.assertFalse(self.app.account_autocreate)

            # return 404 (as account is not found) and don't cache container
            test_status_map((404, 404, 404), 404, None, 404)

            # cache a 204 for the account because it's sort of like it
            # exists
            self.app.account_autocreate = True
            test_status_map((404, 404, 404), 404, None, 204)

    def test_PUT_policy_headers(self):
        backend_requests = []

        def capture_requests(ipaddr, port, device, partition, method,
                             path, headers=None, query_string=None):
            if method == 'PUT':
                backend_requests.append(headers)

        def test_policy(requested_policy):
            with save_globals():
                mock_conn = set_http_connect(200, 201, 201, 201,
                                             give_connect=capture_requests)
                self.app.memcache.store = {}
                req = Request.blank('/v1/a/test', method='PUT',
                                    headers={'Content-Length': 0})
                if requested_policy:
                    expected_policy = requested_policy
                    req.headers['X-Storage-Policy'] = policy.name
                else:
                    expected_policy = POLICIES.default
                res = req.get_response(self.app)
                if expected_policy.is_deprecated:
                    self.assertEqual(res.status_int, 400)
                    self.assertEqual(0, len(backend_requests))
                    expected = 'is deprecated'
                    self.assertIn(expected, res.body,
                                  '%r did not include %r' % (
                                      res.body, expected))
                    return
                self.assertEqual(res.status_int, 201)
                self.assertEqual(
                    expected_policy.object_ring.replicas,
                    len(backend_requests))
                for headers in backend_requests:
                    if not requested_policy:
                        self.assertNotIn('X-Backend-Storage-Policy-Index',
                                         headers)
                        self.assertIn('X-Backend-Storage-Policy-Default',
                                      headers)
                        self.assertEqual(
                            int(expected_policy),
                            int(headers['X-Backend-Storage-Policy-Default']))
                    else:
                        self.assertIn('X-Backend-Storage-Policy-Index',
                                      headers)
                        self.assertEqual(int(headers
                                         ['X-Backend-Storage-Policy-Index']),
                                         int(policy))
                # make sure all mocked responses are consumed
                self.assertRaises(StopIteration, mock_conn.code_iter.next)

        test_policy(None)  # no policy header
        for policy in POLICIES:
            backend_requests = []  # reset backend requests
            test_policy(policy)

    def test_PUT(self):
        with save_globals():
            controller = proxy_server.ContainerController(self.app, 'account',
                                                          'container')

            def test_status_map(statuses, expected, **kwargs):
                set_http_connect(*statuses, **kwargs)
                self.app.memcache.store = {}
                req = Request.blank('/v1/a/c', {})
                req.content_length = 0
                self.app.update_request(req)
                res = controller.PUT(req)
                expected = str(expected)
                self.assertEqual(res.status[:len(expected)], expected)

            test_status_map((200, 201, 201, 201), 201, missing_container=True)
            test_status_map((200, 201, 201, 500), 201, missing_container=True)
            test_status_map((200, 204, 404, 404), 404, missing_container=True)
            test_status_map((200, 204, 500, 404), 503, missing_container=True)
            self.assertFalse(self.app.account_autocreate)
            test_status_map((404, 404, 404), 404, missing_container=True)
            self.app.account_autocreate = True
            # fail to retrieve account info
            test_status_map(
                (503, 503, 503),  # account_info fails on 503
                404, missing_container=True)
            # account fail after creation
            test_status_map(
                (404, 404, 404,   # account_info fails on 404
                 201, 201, 201,   # PUT account
                 404, 404, 404),  # account_info fail
                404, missing_container=True)
            test_status_map(
                (503, 503, 404,   # account_info fails on 404
                 503, 503, 503,   # PUT account
                 503, 503, 404),  # account_info fail
                404, missing_container=True)
            # put fails
            test_status_map(
                (404, 404, 404,   # account_info fails on 404
                 201, 201, 201,   # PUT account
                 200,             # account_info success
                 503, 503, 201),  # put container fail
                503, missing_container=True)
            # all goes according to plan
            test_status_map(
                (404, 404, 404,   # account_info fails on 404
                 201, 201, 201,   # PUT account
                 200,             # account_info success
                 201, 201, 201),  # put container success
                201, missing_container=True)
            test_status_map(
                (503, 404, 404,   # account_info fails on 404
                 503, 201, 201,   # PUT account
                 503, 200,        # account_info success
                 503, 201, 201),  # put container success
                201, missing_container=True)

    def test_PUT_autocreate_account_with_sysmeta(self):
        # x-account-sysmeta headers in a container PUT request should be
        # transferred to the account autocreate PUT request
        with save_globals():
            controller = proxy_server.ContainerController(self.app, 'account',
                                                          'container')

            def test_status_map(statuses, expected, headers=None, **kwargs):
                set_http_connect(*statuses, **kwargs)
                self.app.memcache.store = {}
                req = Request.blank('/v1/a/c', {}, headers=headers)
                req.content_length = 0
                self.app.update_request(req)
                res = controller.PUT(req)
                expected = str(expected)
                self.assertEqual(res.status[:len(expected)], expected)

            self.app.account_autocreate = True
            calls = []
            callback = _make_callback_func(calls)
            key, value = 'X-Account-Sysmeta-Blah', 'something'
            headers = {key: value}

            # all goes according to plan
            test_status_map(
                (404, 404, 404,   # account_info fails on 404
                 201, 201, 201,   # PUT account
                 200,             # account_info success
                 201, 201, 201),  # put container success
                201, missing_container=True,
                headers=headers,
                give_connect=callback)

            self.assertEqual(10, len(calls))
            for call in calls[3:6]:
                self.assertEqual('/account', call['path'])
                self.assertIn(key, call['headers'],
                              '%s call, key %s missing in headers %s' % (
                                  call['method'], key, call['headers']))
                self.assertEqual(value, call['headers'][key])

    def test_POST(self):
        with save_globals():
            controller = proxy_server.ContainerController(self.app, 'account',
                                                          'container')

            def test_status_map(statuses, expected, **kwargs):
                set_http_connect(*statuses, **kwargs)
                self.app.memcache.store = {}
                req = Request.blank('/v1/a/c', {})
                req.content_length = 0
                self.app.update_request(req)
                res = controller.POST(req)
                expected = str(expected)
                self.assertEqual(res.status[:len(expected)], expected)

            test_status_map((200, 201, 201, 201), 201, missing_container=True)
            test_status_map((200, 201, 201, 500), 201, missing_container=True)
            test_status_map((200, 204, 404, 404), 404, missing_container=True)
            test_status_map((200, 204, 500, 404), 503, missing_container=True)
            self.assertFalse(self.app.account_autocreate)
            test_status_map((404, 404, 404), 404, missing_container=True)
            self.app.account_autocreate = True
            test_status_map((404, 404, 404), 404, missing_container=True)

    def test_PUT_max_containers_per_account(self):
        with save_globals():
            self.app.max_containers_per_account = 12346
            controller = proxy_server.ContainerController(self.app, 'account',
                                                          'container')
            self.assert_status_map(controller.PUT,
                                   (200, 201, 201, 201), 201,
                                   missing_container=True)

            self.app.max_containers_per_account = 12345
            controller = proxy_server.ContainerController(self.app, 'account',
                                                          'container')
            self.assert_status_map(controller.PUT,
                                   (200, 200, 201, 201, 201), 201,
                                   missing_container=True)

            controller = proxy_server.ContainerController(self.app, 'account',
                                                          'container_new')

            self.assert_status_map(controller.PUT, (200, 404, 404, 404), 403,
                                   missing_container=True)

            self.app.max_containers_per_account = 12345
            self.app.max_containers_whitelist = ['account']
            controller = proxy_server.ContainerController(self.app, 'account',
                                                          'container')
            self.assert_status_map(controller.PUT,
                                   (200, 201, 201, 201), 201,
                                   missing_container=True)

    def test_PUT_max_container_name_length(self):
        with save_globals():
            limit = constraints.MAX_CONTAINER_NAME_LENGTH
            controller = proxy_server.ContainerController(self.app, 'account',
                                                          '1' * limit)
            self.assert_status_map(controller.PUT,
                                   (200, 201, 201, 201), 201,
                                   missing_container=True)
            controller = proxy_server.ContainerController(self.app, 'account',
                                                          '2' * (limit + 1))
            self.assert_status_map(controller.PUT, (201, 201, 201), 400,
                                   missing_container=True)

    def test_PUT_connect_exceptions(self):
        with save_globals():
            controller = proxy_server.ContainerController(self.app, 'account',
                                                          'container')
            self.assert_status_map(controller.PUT, (200, 201, 201, -1), 201,
                                   missing_container=True)
            self.assert_status_map(controller.PUT, (200, 201, -1, -1), 503,
                                   missing_container=True)
            self.assert_status_map(controller.PUT, (200, 503, 503, -1), 503,
                                   missing_container=True)

    def test_acc_missing_returns_404(self):
        for meth in ('DELETE', 'PUT'):
            with save_globals():
                self.app.memcache = FakeMemcacheReturnsNone()
                self.app._error_limiting = {}
                controller = proxy_server.ContainerController(self.app,
                                                              'account',
                                                              'container')
                if meth == 'PUT':
                    set_http_connect(200, 200, 200, 200, 200, 200,
                                     missing_container=True)
                else:
                    set_http_connect(200, 200, 200, 200)
                self.app.memcache.store = {}
                req = Request.blank('/v1/a/c',
                                    environ={'REQUEST_METHOD': meth})
                self.app.update_request(req)
                resp = getattr(controller, meth)(req)
                self.assertEqual(resp.status_int, 200)

                set_http_connect(404, 404, 404, 200, 200, 200)
                # Make sure it is a blank request wthout env caching
                req = Request.blank('/v1/a/c',
                                    environ={'REQUEST_METHOD': meth})
                resp = getattr(controller, meth)(req)
                self.assertEqual(resp.status_int, 404)

                set_http_connect(503, 404, 404)
                # Make sure it is a blank request wthout env caching
                req = Request.blank('/v1/a/c',
                                    environ={'REQUEST_METHOD': meth})
                resp = getattr(controller, meth)(req)
                self.assertEqual(resp.status_int, 404)

                set_http_connect(503, 404, raise_exc=True)
                # Make sure it is a blank request wthout env caching
                req = Request.blank('/v1/a/c',
                                    environ={'REQUEST_METHOD': meth})
                resp = getattr(controller, meth)(req)
                self.assertEqual(resp.status_int, 404)

                for dev in self.app.account_ring.devs:
                    set_node_errors(self.app, dev,
                                    self.app.error_suppression_limit + 1,
                                    time.time())
                set_http_connect(200, 200, 200, 200, 200, 200)
                # Make sure it is a blank request wthout env caching
                req = Request.blank('/v1/a/c',
                                    environ={'REQUEST_METHOD': meth})
                resp = getattr(controller, meth)(req)
                self.assertEqual(resp.status_int, 404)

    def test_put_locking(self):

        class MockMemcache(FakeMemcache):

            def __init__(self, allow_lock=None):
                self.allow_lock = allow_lock
                super(MockMemcache, self).__init__()

            @contextmanager
            def soft_lock(self, key, timeout=0, retries=5):
                if self.allow_lock:
                    yield True
                else:
                    raise NotImplementedError

        with save_globals():
            controller = proxy_server.ContainerController(self.app, 'account',
                                                          'container')
            self.app.memcache = MockMemcache(allow_lock=True)
            set_http_connect(200, 201, 201, 201,
                             missing_container=True)
            req = Request.blank('/v1/a/c', environ={'REQUEST_METHOD': 'PUT'})
            self.app.update_request(req)
            res = controller.PUT(req)
            self.assertEqual(res.status_int, 201)

    def test_error_limiting(self):
        with save_globals():
            controller = proxy_server.ContainerController(self.app, 'account',
                                                          'container')
            container_ring = controller.app.container_ring
            controller.app.sort_nodes = lambda l: l
            self.assert_status_map(controller.HEAD, (200, 503, 200, 200), 200,
                                   missing_container=False)

            self.assertEqual(
                node_error_count(controller.app, container_ring.devs[0]), 2)
            self.assertTrue(
                node_last_error(controller.app, container_ring.devs[0])
                is not None)
            for _junk in range(self.app.error_suppression_limit):
                self.assert_status_map(controller.HEAD,
                                       (200, 503, 503, 503), 503)
            self.assertEqual(
                node_error_count(controller.app, container_ring.devs[0]),
                self.app.error_suppression_limit + 1)
            self.assert_status_map(controller.HEAD, (200, 200, 200, 200), 503)
            self.assertTrue(
                node_last_error(controller.app, container_ring.devs[0])
                is not None)
            self.assert_status_map(controller.PUT, (200, 201, 201, 201), 503,
                                   missing_container=True)
            self.assert_status_map(controller.DELETE,
                                   (200, 204, 204, 204), 503)
            self.app.error_suppression_interval = -300
            self.assert_status_map(controller.HEAD, (200, 200, 200, 200), 200)
            self.assert_status_map(controller.DELETE, (200, 204, 204, 204),
                                   404, raise_exc=True)

    def test_DELETE(self):
        with save_globals():
            controller = proxy_server.ContainerController(self.app, 'account',
                                                          'container')
            self.assert_status_map(controller.DELETE,
                                   (200, 204, 204, 204), 204)
            self.assert_status_map(controller.DELETE,
                                   (200, 204, 204, 503), 204)
            self.assert_status_map(controller.DELETE,
                                   (200, 204, 503, 503), 503)
            self.assert_status_map(controller.DELETE,
                                   (200, 204, 404, 404), 404)
            self.assert_status_map(controller.DELETE,
                                   (200, 404, 404, 404), 404)
            self.assert_status_map(controller.DELETE,
                                   (200, 204, 503, 404), 503)

            self.app.memcache = FakeMemcacheReturnsNone()
            # 200: Account check, 404x3: Container check
            self.assert_status_map(controller.DELETE,
                                   (200, 404, 404, 404), 404)

    def test_response_get_accept_ranges_header(self):
        with save_globals():
            set_http_connect(200, 200, body='{}')
            controller = proxy_server.ContainerController(self.app, 'account',
                                                          'container')
            req = Request.blank('/v1/a/c?format=json')
            self.app.update_request(req)
            res = controller.GET(req)
            self.assertIn('accept-ranges', res.headers)
            self.assertEqual(res.headers['accept-ranges'], 'bytes')

    def test_response_head_accept_ranges_header(self):
        with save_globals():
            set_http_connect(200, 200, body='{}')
            controller = proxy_server.ContainerController(self.app, 'account',
                                                          'container')
            req = Request.blank('/v1/a/c?format=json')
            self.app.update_request(req)
            res = controller.HEAD(req)
            self.assertIn('accept-ranges', res.headers)
            self.assertEqual(res.headers['accept-ranges'], 'bytes')

    def test_PUT_metadata(self):
        self.metadata_helper('PUT')

    def test_POST_metadata(self):
        self.metadata_helper('POST')

    def metadata_helper(self, method):
        for test_header, test_value in (
                ('X-Container-Meta-TestHeader', 'TestValue'),
                ('X-Container-Meta-TestHeader', ''),
                ('X-Remove-Container-Meta-TestHeader', 'anything'),
                ('X-Container-Read', '.r:*'),
                ('X-Remove-Container-Read', 'anything'),
                ('X-Container-Write', 'anyone'),
                ('X-Remove-Container-Write', 'anything')):
            test_errors = []

            def test_connect(ipaddr, port, device, partition, method, path,
                             headers=None, query_string=None):
                if path == '/a/c':
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
                controller = \
                    proxy_server.ContainerController(self.app, 'a', 'c')
                set_http_connect(200, 201, 201, 201, give_connect=test_connect)
                req = Request.blank(
                    '/v1/a/c',
                    environ={'REQUEST_METHOD': method, 'swift_owner': True},
                    headers={test_header: test_value})
                self.app.update_request(req)
                getattr(controller, method)(req)
                self.assertEqual(test_errors, [])

    def test_PUT_bad_metadata(self):
        self.bad_metadata_helper('PUT')

    def test_POST_bad_metadata(self):
        self.bad_metadata_helper('POST')

    def bad_metadata_helper(self, method):
        with save_globals():
            controller = proxy_server.ContainerController(self.app, 'a', 'c')
            set_http_connect(200, 201, 201, 201)
            req = Request.blank('/v1/a/c', environ={'REQUEST_METHOD': method})
            self.app.update_request(req)
            resp = getattr(controller, method)(req)
            self.assertEqual(resp.status_int, 201)

            set_http_connect(201, 201, 201)
            req = Request.blank('/v1/a/c', environ={'REQUEST_METHOD': method},
                                headers={'X-Container-Meta-' +
                                ('a' * constraints.MAX_META_NAME_LENGTH): 'v'})
            self.app.update_request(req)
            resp = getattr(controller, method)(req)
            self.assertEqual(resp.status_int, 201)
            set_http_connect(201, 201, 201)
            req = Request.blank(
                '/v1/a/c', environ={'REQUEST_METHOD': method},
                headers={'X-Container-Meta-' +
                         ('a' * (constraints.MAX_META_NAME_LENGTH + 1)): 'v'})
            self.app.update_request(req)
            resp = getattr(controller, method)(req)
            self.assertEqual(resp.status_int, 400)

            set_http_connect(201, 201, 201)
            req = Request.blank('/v1/a/c', environ={'REQUEST_METHOD': method},
                                headers={'X-Container-Meta-Too-Long':
                                'a' * constraints.MAX_META_VALUE_LENGTH})
            self.app.update_request(req)
            resp = getattr(controller, method)(req)
            self.assertEqual(resp.status_int, 201)
            set_http_connect(201, 201, 201)
            req = Request.blank('/v1/a/c', environ={'REQUEST_METHOD': method},
                                headers={'X-Container-Meta-Too-Long':
                                'a' * (constraints.MAX_META_VALUE_LENGTH + 1)})
            self.app.update_request(req)
            resp = getattr(controller, method)(req)
            self.assertEqual(resp.status_int, 400)

            set_http_connect(201, 201, 201)
            headers = {}
            for x in range(constraints.MAX_META_COUNT):
                headers['X-Container-Meta-%d' % x] = 'v'
            req = Request.blank('/v1/a/c', environ={'REQUEST_METHOD': method},
                                headers=headers)
            self.app.update_request(req)
            resp = getattr(controller, method)(req)
            self.assertEqual(resp.status_int, 201)
            set_http_connect(201, 201, 201)
            headers = {}
            for x in range(constraints.MAX_META_COUNT + 1):
                headers['X-Container-Meta-%d' % x] = 'v'
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
                headers['X-Container-Meta-%04d' % x] = header_value
                x += 1
            if constraints.MAX_META_OVERALL_SIZE - size > 1:
                headers['X-Container-Meta-a'] = \
                    'a' * (constraints.MAX_META_OVERALL_SIZE - size - 1)
            req = Request.blank('/v1/a/c', environ={'REQUEST_METHOD': method},
                                headers=headers)
            self.app.update_request(req)
            resp = getattr(controller, method)(req)
            self.assertEqual(resp.status_int, 201)
            set_http_connect(201, 201, 201)
            headers['X-Container-Meta-a'] = \
                'a' * (constraints.MAX_META_OVERALL_SIZE - size)
            req = Request.blank('/v1/a/c', environ={'REQUEST_METHOD': method},
                                headers=headers)
            self.app.update_request(req)
            resp = getattr(controller, method)(req)
            self.assertEqual(resp.status_int, 400)

    def test_POST_calls_clean_acl(self):
        called = [False]

        def clean_acl(header, value):
            called[0] = True
            raise ValueError('fake error')
        with save_globals():
            set_http_connect(200, 201, 201, 201)
            controller = proxy_server.ContainerController(self.app, 'account',
                                                          'container')
            req = Request.blank('/v1/a/c', environ={'REQUEST_METHOD': 'POST'},
                                headers={'X-Container-Read': '.r:*'})
            req.environ['swift.clean_acl'] = clean_acl
            self.app.update_request(req)
            controller.POST(req)
        self.assertTrue(called[0])
        called[0] = False
        with save_globals():
            set_http_connect(200, 201, 201, 201)
            controller = proxy_server.ContainerController(self.app, 'account',
                                                          'container')
            req = Request.blank('/v1/a/c', environ={'REQUEST_METHOD': 'POST'},
                                headers={'X-Container-Write': '.r:*'})
            req.environ['swift.clean_acl'] = clean_acl
            self.app.update_request(req)
            controller.POST(req)
        self.assertTrue(called[0])

    def test_PUT_calls_clean_acl(self):
        called = [False]

        def clean_acl(header, value):
            called[0] = True
            raise ValueError('fake error')
        with save_globals():
            set_http_connect(200, 201, 201, 201)
            controller = proxy_server.ContainerController(self.app, 'account',
                                                          'container')
            req = Request.blank('/v1/a/c', environ={'REQUEST_METHOD': 'PUT'},
                                headers={'X-Container-Read': '.r:*'})
            req.environ['swift.clean_acl'] = clean_acl
            self.app.update_request(req)
            controller.PUT(req)
        self.assertTrue(called[0])
        called[0] = False
        with save_globals():
            set_http_connect(200, 201, 201, 201)
            controller = proxy_server.ContainerController(self.app, 'account',
                                                          'container')
            req = Request.blank('/v1/a/c', environ={'REQUEST_METHOD': 'PUT'},
                                headers={'X-Container-Write': '.r:*'})
            req.environ['swift.clean_acl'] = clean_acl
            self.app.update_request(req)
            controller.PUT(req)
        self.assertTrue(called[0])

    def test_GET_no_content(self):
        with save_globals():
            set_http_connect(200, 204, 204, 204)
            controller = proxy_server.ContainerController(self.app, 'a', 'c')
            req = Request.blank('/v1/a/c')
            self.app.update_request(req)
            res = controller.GET(req)
            self.assertEqual(res.status_int, 204)
            ic = res.environ['swift.infocache']
            self.assertEqual(ic['container/a/c']['status'], 204)
            self.assertEqual(res.content_length, 0)
            self.assertNotIn('transfer-encoding', res.headers)

    def test_GET_calls_authorize(self):
        called = [False]

        def authorize(req):
            called[0] = True
            return HTTPUnauthorized(request=req)
        with save_globals():
            set_http_connect(200, 201, 201, 201)
            controller = proxy_server.ContainerController(self.app, 'a', 'c')
            req = Request.blank('/v1/a/c')
            req.environ['swift.authorize'] = authorize
            self.app.update_request(req)
            res = controller.GET(req)
        self.assertEqual(
            res.environ['swift.infocache']['container/a/c']['status'],
            201)
        self.assertTrue(called[0])

    def test_HEAD_calls_authorize(self):
        called = [False]

        def authorize(req):
            called[0] = True
            return HTTPUnauthorized(request=req)
        with save_globals():
            set_http_connect(200, 201, 201, 201)
            controller = proxy_server.ContainerController(self.app, 'a', 'c')
            req = Request.blank('/v1/a/c', {'REQUEST_METHOD': 'HEAD'})
            req.environ['swift.authorize'] = authorize
            self.app.update_request(req)
            controller.HEAD(req)
        self.assertTrue(called[0])

    def test_unauthorized_requests_when_account_not_found(self):
        # verify unauthorized container requests always return response
        # from swift.authorize
        called = [0, 0]

        def authorize(req):
            called[0] += 1
            return HTTPUnauthorized(request=req)

        def account_info(*args):
            called[1] += 1
            return None, None, None

        def _do_test(method):
            with save_globals():
                swift.proxy.controllers.Controller.account_info = account_info
                app = proxy_server.Application(None, FakeMemcache(),
                                               account_ring=FakeRing(),
                                               container_ring=FakeRing())
                set_http_connect(201, 201, 201)
                req = Request.blank('/v1/a/c', {'REQUEST_METHOD': method})
                req.environ['swift.authorize'] = authorize
                self.app.update_request(req)
                res = app.handle_request(req)
            return res

        for method in ('PUT', 'POST', 'DELETE'):
            # no delay_denial on method, expect one call to authorize
            called = [0, 0]
            res = _do_test(method)
            self.assertEqual(401, res.status_int)
            self.assertEqual([1, 0], called)

        for method in ('HEAD', 'GET'):
            # delay_denial on method, expect two calls to authorize
            called = [0, 0]
            res = _do_test(method)
            self.assertEqual(401, res.status_int)
            self.assertEqual([2, 1], called)

    def test_authorized_requests_when_account_not_found(self):
        # verify authorized container requests always return 404 when
        # account not found
        called = [0, 0]

        def authorize(req):
            called[0] += 1

        def account_info(*args):
            called[1] += 1
            return None, None, None

        def _do_test(method):
            with save_globals():
                swift.proxy.controllers.Controller.account_info = account_info
                app = proxy_server.Application(None, FakeMemcache(),
                                               account_ring=FakeRing(),
                                               container_ring=FakeRing())
                set_http_connect(201, 201, 201)
                req = Request.blank('/v1/a/c', {'REQUEST_METHOD': method})
                req.environ['swift.authorize'] = authorize
                self.app.update_request(req)
                res = app.handle_request(req)
            return res

        for method in ('PUT', 'POST', 'DELETE', 'HEAD', 'GET'):
            # expect one call to authorize
            called = [0, 0]
            res = _do_test(method)
            self.assertEqual(404, res.status_int)
            self.assertEqual([1, 1], called)

    def test_OPTIONS_get_info_drops_origin(self):
        with save_globals():
            controller = proxy_server.ContainerController(self.app, 'a', 'c')

            count = [0]

            def my_get_info(app, env, account, container=None,
                            ret_not_found=False, swift_source=None):
                if count[0] > 11:
                    return {}
                count[0] += 1
                if not container:
                    return {'some': 'stuff'}
                return proxy_base.was_get_info(
                    app, env, account, container, ret_not_found, swift_source)

            proxy_base.was_get_info = proxy_base.get_info
            with mock.patch.object(proxy_base, 'get_info', my_get_info):
                proxy_base.get_info = my_get_info
                req = Request.blank(
                    '/v1/a/c',
                    {'REQUEST_METHOD': 'OPTIONS'},
                    headers={'Origin': 'http://foo.com',
                             'Access-Control-Request-Method': 'GET'})
                controller.OPTIONS(req)
                self.assertLess(count[0], 11)

    def test_OPTIONS(self):
        with save_globals():
            controller = proxy_server.ContainerController(self.app, 'a', 'c')

            def my_empty_container_info(*args):
                return {}
            controller.container_info = my_empty_container_info
            req = Request.blank(
                '/v1/a/c',
                {'REQUEST_METHOD': 'OPTIONS'},
                headers={'Origin': 'http://foo.com',
                         'Access-Control-Request-Method': 'GET'})
            resp = controller.OPTIONS(req)
            self.assertEqual(401, resp.status_int)

            def my_empty_origin_container_info(*args):
                return {'cors': {'allow_origin': None}}
            controller.container_info = my_empty_origin_container_info
            req = Request.blank(
                '/v1/a/c',
                {'REQUEST_METHOD': 'OPTIONS'},
                headers={'Origin': 'http://foo.com',
                         'Access-Control-Request-Method': 'GET'})
            resp = controller.OPTIONS(req)
            self.assertEqual(401, resp.status_int)

            def my_container_info(*args):
                return {
                    'cors': {
                        'allow_origin': 'http://foo.bar:8080 https://foo.bar',
                        'max_age': '999',
                    }
                }
            controller.container_info = my_container_info
            req = Request.blank(
                '/v1/a/c',
                {'REQUEST_METHOD': 'OPTIONS'},
                headers={'Origin': 'https://foo.bar',
                         'Access-Control-Request-Method': 'GET'})
            req.content_length = 0
            resp = controller.OPTIONS(req)
            self.assertEqual(200, resp.status_int)
            self.assertEqual(
                'https://foo.bar',
                resp.headers['access-control-allow-origin'])
            for verb in 'OPTIONS GET POST PUT DELETE HEAD'.split():
                self.assertIn(verb,
                              resp.headers['access-control-allow-methods'])
            self.assertEqual(
                len(resp.headers['access-control-allow-methods'].split(', ')),
                6)
            self.assertEqual('999', resp.headers['access-control-max-age'])
            req = Request.blank(
                '/v1/a/c',
                {'REQUEST_METHOD': 'OPTIONS'},
                headers={'Origin': 'https://foo.bar'})
            req.content_length = 0
            resp = controller.OPTIONS(req)
            self.assertEqual(401, resp.status_int)
            req = Request.blank('/v1/a/c', {'REQUEST_METHOD': 'OPTIONS'})
            req.content_length = 0
            resp = controller.OPTIONS(req)
            self.assertEqual(200, resp.status_int)
            for verb in 'OPTIONS GET POST PUT DELETE HEAD'.split():
                self.assertIn(verb, resp.headers['Allow'])
            self.assertEqual(len(resp.headers['Allow'].split(', ')), 6)
            req = Request.blank(
                '/v1/a/c',
                {'REQUEST_METHOD': 'OPTIONS'},
                headers={'Origin': 'http://foo.bar',
                         'Access-Control-Request-Method': 'GET'})
            resp = controller.OPTIONS(req)
            self.assertEqual(401, resp.status_int)
            req = Request.blank(
                '/v1/a/c',
                {'REQUEST_METHOD': 'OPTIONS'},
                headers={'Origin': 'http://foo.bar',
                         'Access-Control-Request-Method': 'GET'})
            controller.app.cors_allow_origin = ['http://foo.bar', ]
            resp = controller.OPTIONS(req)
            self.assertEqual(200, resp.status_int)

            def my_container_info_wildcard(*args):
                return {
                    'cors': {
                        'allow_origin': '*',
                        'max_age': '999',
                    }
                }
            controller.container_info = my_container_info_wildcard
            req = Request.blank(
                '/v1/a/c/o.jpg',
                {'REQUEST_METHOD': 'OPTIONS'},
                headers={'Origin': 'https://bar.baz',
                         'Access-Control-Request-Method': 'GET'})
            req.content_length = 0
            resp = controller.OPTIONS(req)
            self.assertEqual(200, resp.status_int)
            self.assertEqual('*', resp.headers['access-control-allow-origin'])
            for verb in 'OPTIONS GET POST PUT DELETE HEAD'.split():
                self.assertIn(verb,
                              resp.headers['access-control-allow-methods'])
            self.assertEqual(
                len(resp.headers['access-control-allow-methods'].split(', ')),
                6)
            self.assertEqual('999', resp.headers['access-control-max-age'])

            req = Request.blank(
                '/v1/a/c/o.jpg',
                {'REQUEST_METHOD': 'OPTIONS'},
                headers={'Origin': 'https://bar.baz',
                         'Access-Control-Request-Headers':
                         'x-foo, x-bar, x-auth-token',
                         'Access-Control-Request-Method': 'GET'}
            )
            req.content_length = 0
            resp = controller.OPTIONS(req)
            self.assertEqual(200, resp.status_int)
            self.assertEqual(
                sortHeaderNames('x-foo, x-bar, x-auth-token'),
                sortHeaderNames(resp.headers['access-control-allow-headers']))

    def test_CORS_valid(self):
        with save_globals():
            controller = proxy_server.ContainerController(self.app, 'a', 'c')

            def stubContainerInfo(*args):
                return {
                    'cors': {
                        'allow_origin': 'http://foo.bar'
                    }
                }
            controller.container_info = stubContainerInfo

            def containerGET(controller, req):
                return Response(headers={
                    'X-Container-Meta-Color': 'red',
                    'X-Super-Secret': 'hush',
                })

            req = Request.blank(
                '/v1/a/c',
                {'REQUEST_METHOD': 'GET'},
                headers={'Origin': 'http://foo.bar'})

            resp = cors_validation(containerGET)(controller, req)

            self.assertEqual(200, resp.status_int)
            self.assertEqual('http://foo.bar',
                             resp.headers['access-control-allow-origin'])
            self.assertEqual('red', resp.headers['x-container-meta-color'])
            # X-Super-Secret is in the response, but not "exposed"
            self.assertEqual('hush', resp.headers['x-super-secret'])
            self.assertIn('access-control-expose-headers', resp.headers)
            exposed = set(
                h.strip() for h in
                resp.headers['access-control-expose-headers'].split(','))
            expected_exposed = set([
                'cache-control', 'content-language', 'content-type', 'expires',
                'last-modified', 'pragma', 'etag', 'x-timestamp', 'x-trans-id',
                'x-openstack-request-id', 'x-container-meta-color'])
            self.assertEqual(expected_exposed, exposed)

    def _gather_x_account_headers(self, controller_call, req, *connect_args,
                                  **kwargs):
        seen_headers = []
        to_capture = ('X-Account-Partition', 'X-Account-Host',
                      'X-Account-Device')

        def capture_headers(ipaddr, port, device, partition, method,
                            path, headers=None, query_string=None):
            captured = {}
            for header in to_capture:
                captured[header] = headers.get(header)
            seen_headers.append(captured)

        with save_globals():
            self.app.allow_account_management = True

            set_http_connect(*connect_args, give_connect=capture_headers,
                             **kwargs)
            resp = controller_call(req)
            self.assertEqual(2, resp.status_int // 100)  # sanity check

            # don't care about the account HEAD, so throw away the
            # first element
            return sorted(seen_headers[1:],
                          key=lambda d: d['X-Account-Host'] or 'Z')

    def test_PUT_x_account_headers_with_fewer_account_replicas(self):
        self.app.account_ring.set_replicas(2)
        req = Request.blank('/v1/a/c', headers={'': ''})
        controller = proxy_server.ContainerController(self.app, 'a', 'c')

        seen_headers = self._gather_x_account_headers(
            controller.PUT, req,
            200, 201, 201, 201)    # HEAD PUT PUT PUT
        self.assertEqual(seen_headers, [
            {'X-Account-Host': '10.0.0.0:1000',
             'X-Account-Partition': '0',
             'X-Account-Device': 'sda'},
            {'X-Account-Host': '10.0.0.1:1001',
             'X-Account-Partition': '0',
             'X-Account-Device': 'sdb'},
            {'X-Account-Host': None,
             'X-Account-Partition': None,
             'X-Account-Device': None}
        ])

    def test_PUT_x_account_headers_with_more_account_replicas(self):
        self.app.account_ring.set_replicas(4)
        req = Request.blank('/v1/a/c', headers={'': ''})
        controller = proxy_server.ContainerController(self.app, 'a', 'c')

        seen_headers = self._gather_x_account_headers(
            controller.PUT, req,
            200, 201, 201, 201)    # HEAD PUT PUT PUT
        self.assertEqual(seen_headers, [
            {'X-Account-Host': '10.0.0.0:1000,10.0.0.3:1003',
             'X-Account-Partition': '0',
             'X-Account-Device': 'sda,sdd'},
            {'X-Account-Host': '10.0.0.1:1001',
             'X-Account-Partition': '0',
             'X-Account-Device': 'sdb'},
            {'X-Account-Host': '10.0.0.2:1002',
             'X-Account-Partition': '0',
             'X-Account-Device': 'sdc'}
        ])

    def test_DELETE_x_account_headers_with_fewer_account_replicas(self):
        self.app.account_ring.set_replicas(2)
        req = Request.blank('/v1/a/c', headers={'': ''})
        controller = proxy_server.ContainerController(self.app, 'a', 'c')

        seen_headers = self._gather_x_account_headers(
            controller.DELETE, req,
            200, 204, 204, 204)    # HEAD DELETE DELETE DELETE
        self.assertEqual(seen_headers, [
            {'X-Account-Host': '10.0.0.0:1000',
             'X-Account-Partition': '0',
             'X-Account-Device': 'sda'},
            {'X-Account-Host': '10.0.0.1:1001',
             'X-Account-Partition': '0',
             'X-Account-Device': 'sdb'},
            {'X-Account-Host': None,
             'X-Account-Partition': None,
             'X-Account-Device': None}
        ])

    def test_DELETE_x_account_headers_with_more_account_replicas(self):
        self.app.account_ring.set_replicas(4)
        req = Request.blank('/v1/a/c', headers={'': ''})
        controller = proxy_server.ContainerController(self.app, 'a', 'c')

        seen_headers = self._gather_x_account_headers(
            controller.DELETE, req,
            200, 204, 204, 204)    # HEAD DELETE DELETE DELETE
        self.assertEqual(seen_headers, [
            {'X-Account-Host': '10.0.0.0:1000,10.0.0.3:1003',
             'X-Account-Partition': '0',
             'X-Account-Device': 'sda,sdd'},
            {'X-Account-Host': '10.0.0.1:1001',
             'X-Account-Partition': '0',
             'X-Account-Device': 'sdb'},
            {'X-Account-Host': '10.0.0.2:1002',
             'X-Account-Partition': '0',
             'X-Account-Device': 'sdc'}
        ])

    def test_PUT_backed_x_timestamp_header(self):
        timestamps = []

        def capture_timestamps(*args, **kwargs):
            headers = kwargs['headers']
            timestamps.append(headers.get('X-Timestamp'))

        req = Request.blank('/v1/a/c', method='PUT', headers={'': ''})
        with save_globals():
            new_connect = set_http_connect(200,  # account existence check
                                           201, 201, 201,
                                           give_connect=capture_timestamps)
            resp = self.app.handle_request(req)

        # sanity
        self.assertRaises(StopIteration, new_connect.code_iter.next)
        self.assertEqual(2, resp.status_int // 100)

        timestamps.pop(0)  # account existence check
        self.assertEqual(3, len(timestamps))
        for timestamp in timestamps:
            self.assertEqual(timestamp, timestamps[0])
            self.assertTrue(re.match('[0-9]{10}\.[0-9]{5}', timestamp))

    def test_DELETE_backed_x_timestamp_header(self):
        timestamps = []

        def capture_timestamps(*args, **kwargs):
            headers = kwargs['headers']
            timestamps.append(headers.get('X-Timestamp'))

        req = Request.blank('/v1/a/c', method='DELETE', headers={'': ''})
        self.app.update_request(req)
        with save_globals():
            new_connect = set_http_connect(200,  # account existence check
                                           201, 201, 201,
                                           give_connect=capture_timestamps)
            resp = self.app.handle_request(req)

        # sanity
        self.assertRaises(StopIteration, new_connect.code_iter.next)
        self.assertEqual(2, resp.status_int // 100)

        timestamps.pop(0)  # account existence check
        self.assertEqual(3, len(timestamps))
        for timestamp in timestamps:
            self.assertEqual(timestamp, timestamps[0])
            self.assertTrue(re.match('[0-9]{10}\.[0-9]{5}', timestamp))

    def test_node_read_timeout_retry_to_container(self):
        with save_globals():
            req = Request.blank('/v1/a/c', environ={'REQUEST_METHOD': 'GET'})
            self.app.node_timeout = 0.1
            set_http_connect(200, 200, 200, body='abcdef', slow=[1.0, 1.0])
            resp = req.get_response(self.app)
            got_exc = False
            try:
                resp.body
            except ChunkReadTimeout:
                got_exc = True
            self.assertTrue(got_exc)


@patch_policies(
    [StoragePolicy(0, 'zero', True, object_ring=FakeRing(replicas=4))])
class TestContainerController4Replicas(ContainerControllerMeta, TestRingBase):

    CONTAINER_REPLICAS = 4

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


if __name__ == '__main__':
    unittest.main()
