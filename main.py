#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright 2018 New Vector Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import copy
import itertools
import json
import logging.config
import re
import socket
from socket import inet_pton
from time import sleep

from matrix_client.client import MatrixClient
from matrix_client.errors import MatrixRequestError
import six
import yaml

# events sent fewer than this many seconds after the ACL event will be
# tolerated
ACL_VIOLATION_GRACE_SECONDS = 60

logger = logging.getLogger("vdh_matrix.bot")


class BotMatrixClient(MatrixClient):
    def __init__(self, *args, **kwargs):
        # inhibit the initial sync duriing init.
        self._inhibit_sync = True
        super(BotMatrixClient, self).__init__(*args, **kwargs)
        self._inhibit_sync = False

        self._new_room_listeners = []
        self._sync_loop_listeners = []

    def _sync(self, *args, **kwargs):
        if self._inhibit_sync:
            return
        sync_token = self.sync_token
        result = super(BotMatrixClient, self)._sync(*args, **kwargs)
        for listener in self._sync_loop_listeners:
            listener(sync_token)
        return result

    def _mkroom(self, room_id):
        room = super(BotMatrixClient, self)._mkroom(room_id)

        for listener in self._new_room_listeners:
            listener(room)

    def add_new_room_listener(self, listener):
        self._new_room_listeners.append(listener)

    def add_sync_loop_listener(self, listener):
        self._sync_loop_listeners.append(listener)


class Bot(object):
    def __init__(self, config):
        self._client = BotMatrixClient(
            config['hs_url'],
            token=config['access_token'],
            user_id=config['user_id'],
        )

        # map from room id to RoomListener
        self._listeners = {}

        # we need federation format events.
        self._client.sync_filter = json.dumps({
            'room': {
                'timeline': {
                    'limit': 20,
                }
            },
            'event_format': 'federation',
        })

        self._client.add_new_room_listener(self._on_new_room)
        self._client.add_sync_loop_listener(self._on_sync_loop)

    def run(self):
        self._client.listen_forever(exception_handler=self._sync_exception_handler)
        logger.info('Bot started.')

    def _on_new_room(self, room):
        """
        Args:
            room (matrix_client.room.Room):
        """
        logger.info('Adding listener for room %s', room.room_id)
        self._listeners[room.room_id] = RoomListener(room)

    def _on_sync_loop(self, sync_token):
        for l in self._listeners.values():
            l.on_sync_loop()

    @staticmethod
    def _sync_exception_handler(exception):
        # sleep to avoid tight-looping when synapse is down
        sleep(5)


class RoomListener(object):
    def __init__(self, room):
        """
        Args:
            room (matrix_client.room.Room):
        """
        self._room = room
        self._api = room.client.api  # type: matrix_client.api.MatrixHttpApi
        self._violating_events = set()
        self._acl_event = None

        # set to True to indicate we should check for state resets after
        # processing the current sync.
        self._recheck_flag = False

        room.add_state_listener(self._on_acl_event, 'm.room.server_acl')
        room.add_listener(self._on_event)


    def on_sync_loop(self):
        if self._recheck_flag:
            self._recheck_acl()
            self._recheck_flag = False

    def _get_acl_event(self):
        try:
            # TODO: add this to the SDK
            return self._api._send(
                "GET", "/rooms/%s/state/m.room.server_acl/" % (
                    self._room.room_id,
                ),
            )
        except MatrixRequestError as e:
            if e.code == 404:
                err = json.loads(e.content)
                if err['errcode'] == 'M_NOT_FOUND':
                    # no acl in this room
                    return None
            raise

    def _recheck_acl(self):
        # check if the ACL has been reset
        if self._acl_event is None:
            return

        logger.debug("Checking for state-resets in %s", self._room.room_id)
        current_acl = self._get_acl_event()
        if current_acl != self._acl_event["content"]:
            logger.warning(
                "ACL appears to have been state-reset in %s: now %s (was %s)",
                self._room.room_id,
                current_acl, self._acl_event["content"],
            )

            # TODO: put it back.

            # now we have to get the whole room state, so that we can get the
            # full ACL event :/
            s = self._api.get_room_state(self._room.room_id)
            for e in s:
                if e['type'] == 'm.room.server_acl' and e['state_key'] == '':
                    self._acl_event = e
                    break

    def _on_event(self, _room, event):
        event_id = event['event_id']
        logger.debug("Checking acl for %s in %s", event_id, self._room.room_id)
        origin_server = get_origin_server_name(event_id)

        # determine if this event violates the ACL
        if self._acl_event and not server_matches_acl(
            origin_server, self._acl_event["content"],
        ):
            ts_delta = (
                event["origin_server_ts"] - self._acl_event["orgin_server_ts"]
            )
            if ts_delta < ACL_VIOLATION_GRACE_SECONDS * 1000:
                logger.info(
                    'event %s in %s violates ACL, but it was only sent %ims'
                    'after the ACL',
                    event_id, self._room.room_id, ts_delta,
                )
            else:
                logger.info(
                    'event %s in %s violates ACL',
                    event_id, self._room.room_id,
                )
            self._violating_events.add(event_id)
        else:
            # see if this event's prev_events or auth_events reference a
            # violating event.
            for (prev, _hash) in itertools.chain(
                    event.get("prev_events", []),
                    event.get("auth_events", []),
            ):
                if prev in self._violating_events:
                    logger.error(
                        "Event %s in %s references violating event %s: "
                        "consider acling %s",
                        event_id,
                        self._room.room_id, prev, origin_server,
                    )
                    self.add_server_to_acl(origin_server)

        self._recheck_flag = True

    def _on_acl_event(self, state_event):
        logger.info(
            'acl event in %s: %s', self._room.room_id, state_event['content'],
        )
        self._acl_event = state_event

    def add_server_to_acl(self, server_name):
        our_server_name = self._room.client.user_id.split(":", 1)[1]
        if server_name == our_server_name:
            logger.warn(
                "Cowardly refusing to set an ACL on our own server %s",
                server_name,
            )
            return
        newacl = copy.deepcopy(self._acl_event["content"])
        newacl.setdefault("deny", []).append(server_name)
        self.set_acl(newacl)

    def set_acl(self, newacl):
        logger.info('setting new ACL in %s: %s', self._room.room_id, newacl)
        try:
            self._api.send_state_event(
                self._room.room_id,
                "m.room.server_acl",
                content=newacl,
            )
            logger.info("Set new ACL successfully")
        except Exception as e:
            logger.warning(
                "Unable to set ACL in %s: %s", self._room.room_id, e,
            )


def get_origin_server_name(event_id):
    server_name = event_id.split(':', 1)[1]

    # split into host/port parts
    try:
        if server_name[-1] == ']':
            # ipv6 literal, hopefully
            return server_name

        domain_port = server_name.rsplit(":", 1)
        domain = domain_port[0]
        return domain
    except Exception:
        raise ValueError("Invalid server name '%s'" % server_name)


def server_matches_acl(server_name, acl):
    """Check if the given server is allowed by the ACL event

    Args:
        server_name (str): name of server (excluding port)
        acl (dict): body of the acl event

    Returns:
        bool: True if this server is allowed by the ACLs
    """
    logger.debug("Checking %s against acl %s", server_name, acl)

    # first of all, check if literal IPs are blocked, and if so, whether the
    # server name is a literal IP
    allow_ip_literals = acl.get("allow_ip_literals", True)
    if not isinstance(allow_ip_literals, bool):
        logger.warning("Ignorning non-bool allow_ip_literals flag")
        allow_ip_literals = True
    if not allow_ip_literals:
        # check for ipv6 literals. These start with '['.
        if server_name[0] == '[':
            logger.info('ipv6 literal %s failed ACL', server_name)
            return False

        if is_ip_address(server_name):
            logger.info('ipv4 literal %s failed ACL', server_name)
            return False

    # next, check the deny list
    deny = acl.get("deny", [])
    if not isinstance(deny, (list, tuple)):
        logger.warning("Ignorning non-list deny ACL %s", deny)
        deny = []
    for e in deny:
        if _acl_entry_matches(server_name, e):
            logger.info("%s matched deny rule %s", server_name, e)
            return False

    # then the allow list.
    allow = acl.get("allow", [])
    if not isinstance(allow, (list, tuple)):
        logger.warning("Ignorning non-list allow ACL %s", allow)
        allow = []
    for e in allow:
        if _acl_entry_matches(server_name, e):
            logger.debug("%s matched allow rule %s", server_name, e)
            return True

    # everything else should be rejected.
    # logger.info("%s fell through", server_name)
    return False


def _acl_entry_matches(server_name, acl_entry):
    if not isinstance(acl_entry, six.string_types):
        logger.warning(
            "Ignoring non-str ACL entry '%s' (is %s)",
            acl_entry, type(acl_entry),
        )
        return False
    regex = _glob_to_regex(acl_entry)
    return regex.match(server_name)


def _glob_to_regex(glob):
    res = ''
    for c in glob:
        if c == '*':
            res = res + '.*'
        elif c == '?':
            res = res + '.'
        else:
            res = res + re.escape(c)
    return re.compile(res + "\\Z", re.IGNORECASE)


def is_ip_address(server_name):
    try:
        inet_pton(socket.AF_INET, server_name)
        return True
    except socket.error:
        return False
    except ValueError:
        return False


if __name__ == '__main__':
    with open('log_config.yaml', 'r') as f:
        logging.config.dictConfig(yaml.load(f))
    with open('config.yaml', 'r') as conf:
        config = yaml.load(conf)
    bot = Bot(config)
    bot.run()
