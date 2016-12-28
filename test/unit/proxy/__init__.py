# Copyright (c) 2010-2016 OpenStack Foundation
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

""" Swift tests """

from __future__ import print_function
from contextlib import contextmanager

from swift.proxy import controllers as proxy_controllers

from test.unit import (FakeMemcache, fake_http_connect)


def _make_callback_func(calls):
    def callback(ipaddr, port, device, partition, method, path,
                 headers=None, query_string=None, ssl=False):
        context = {}
        context['method'] = method
        context['path'] = path
        context['headers'] = headers or {}
        calls.append(context)
    return callback


def set_http_connect(*args, **kwargs):
    new_connect = fake_http_connect(*args, **kwargs)
    proxy_controllers.base.http_connect = new_connect
    proxy_controllers.obj.http_connect = new_connect
    proxy_controllers.account.http_connect = new_connect
    proxy_controllers.container.http_connect = new_connect
    return new_connect


@contextmanager
def save_globals():
    orig_http_connect = getattr(proxy_controllers.base, 'http_connect',
                                None)
    orig_account_info = getattr(proxy_controllers.Controller,
                                'account_info', None)
    orig_container_info = getattr(proxy_controllers.Controller,
                                  'container_info', None)

    try:
        yield True
    finally:
        proxy_controllers.Controller.account_info = orig_account_info
        proxy_controllers.base.http_connect = orig_http_connect
        proxy_controllers.obj.http_connect = orig_http_connect
        proxy_controllers.account.http_connect = orig_http_connect
        proxy_controllers.container.http_connect = orig_http_connect
        proxy_controllers.Controller.container_info = orig_container_info


class FakeMemcacheReturnsNone(FakeMemcache):

    def get(self, key):
        # Returns None as the timestamp of the container; assumes we're only
        # using the FakeMemcache for container existence checks.
        return None
