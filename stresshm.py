#!/usr/bin/python
# Copyright 2018 Rackspace, US Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import datetime
import multiprocessing
import random
import string
import sys
import time

from octavia.amphorae.backends.health_daemon import health_sender
from oslo_config import cfg
from oslo_db.sqlalchemy import enginefacade
from oslo_log import log as logging
from oslo_utils import uuidutils


CONF = cfg.CONF
LOG = logging.getLogger(__name__)

VIP_NET_ID = uuidutils.generate_uuid()
VIP_PORT_ID = uuidutils.generate_uuid()
VIP_SUBNET_ID = uuidutils.generate_uuid()
VRRP_PORT_ID = uuidutils.generate_uuid()
PROJECT_ID = uuidutils.generate_uuid()
SERVER_GROUP_ID = uuidutils.generate_uuid()
QOS_POLICY_ID = uuidutils.generate_uuid()
COMPUTE_ID = uuidutils.generate_uuid()
IMAGE_ID = uuidutils.generate_uuid()
MEM_SUBNET_ID = uuidutils.generate_uuid()
PREFIX = uuidutils.generate_uuid()


cli_opts = [
    cfg.BoolOpt('db_create_only', default=False,
                help='Populate the database and exit.'),
    cfg.StrOpt('clean_db', metavar='PREFIX',
               help='Deletes all objects with the specified prefix'),
]
cfg.CONF.register_cli_opts(cli_opts)

test_params_opts = [
    cfg.StrOpt('octavia_db_connection',
               required=True,
               help='The octavia database connection string'),
    cfg.IntOpt('load_balancers',
               default=1, min=1,
               help='Number of load balancers to create.'),
    cfg.IntOpt('listeners',
               default=1,
               help='Number of listeners to create.'),
    cfg.IntOpt('pools',
               default=1,
               help='Number of pools to create.'),
    cfg.IntOpt('health_monitors',
               default=1, min=0, max=1,
               help='Number of health managers to create.'),
    cfg.IntOpt('members',
               default=1, min=1, max=65535,
               help='Number of members to create.'),
    cfg.IntOpt('l7policies',
               default=1, min=0,
               help='Number of l7policies to create.'),
    cfg.IntOpt('l7rules',
               default=1, min=0,
               help='Number of l7rules to create.'),
    cfg.IntOpt('heartbeat_interval', default=10,
               help='The fake amphora heartbeat interval.'),
    cfg.IntOpt('test_runtime_secs', default=60,
               help='Time to run the health manager stress test in '
                    'seconds.')
]
cfg.CONF.register_opts(test_params_opts, group='test_params')

health_manager_opts = [
    cfg.StrOpt('heartbeat_key',
               help='UDP heartbeat security key', secret=True),
    cfg.ListOpt('controller_ip_port_list',
                help=('List of controller ip and port pairs for the '
                       'heartbeat receivers. Example 127.0.0.1:5555, '
                       '192.168.0.1:5555'),
                default=[]),
    cfg.IntOpt('heartbeat_interval',
               default=10,
               help=_('Sleep time between sending heartbeats.')),
    cfg.IntOpt('heartbeat_version', default=1,
                help='When set, the heartbeat message will be sent '
                     'using this version.')
]

cfg.CONF.register_opts(health_manager_opts, group='health_manager')

def create_members(session, prefix, pool):
    members = []
    for i in range(CONF.test_params.members):
        name = prefix + '-member' + str(i)
        member_id = uuidutils.generate_uuid()

        # Create Member
        result = session.execute(
            "INSERT INTO member (id, pool_id, project_id, subnet_id, "
            "ip_address, protocol_port, weight, operating_status, enabled, "
            "created_at, updated_at, provisioning_status, name, backup) "
            "VALUES (:id, :pool_id, :project_id, :subnet_id, :ip_address, "
            ":protocol_port, :weight, :operating_status, :enabled, "
            ":created_at, :updated_at, :provisioning_status, :name, :backup);",
            {'id': member_id, 'pool_id': pool['id'], 'project_id': PROJECT_ID,
             'subnet_id': MEM_SUBNET_ID, 'ip_address': '192.0.2.4',
             'protocol_port': i, 'weight': 1,
             'operating_status': 'ONLINE', 'enabled': True,
             'created_at': datetime.datetime.utcnow(),
             'updated_at': datetime.datetime.utcnow(),
             'provisioning_status': 'ACTIVE', 'name': name,
             'backup': False})
        if result.rowcount != 1:
            session.rollback()
            raise Exception(_('Unable to create member in the '
                              'Octavia database.'))
        member = {'name': name, 'id': member_id}
        members.append(member)
    pool['members'] = members

def create_pools(session, prefix, lb, listener):
    pools = []
    for i in range(CONF.test_params.pools):
        name = prefix + '-pool' + str(i)
        pool_id = uuidutils.generate_uuid()

        # Create Pool
        result = session.execute(
            "INSERT INTO pool (id, project_id, name, description, "
            "protocol, lb_algorithm, operating_status, enabled, "
            "load_balancer_id, created_at, updated_at, "
            "provisioning_status) VALUES (:id, :project_id, :name, "
            ":description, :protocol, :lb_algorithm, "
            ":operating_status, :enabled, :load_balancer_id,"
            ":created_at, :updated_at, :provisioning_status);",
            {'id': pool_id, 'project_id': PROJECT_ID, 'name': name,
            'description': 'A pool', 'protocol': 'HTTP',
            'lb_algorithm': 'ROUND_ROBIN', 'operating_status': 'ONLINE',
            'enabled': True, 'load_balancer_id': lb['id'],
            'created_at': datetime.datetime.utcnow(),
            'updated_at': datetime.datetime.utcnow(),
            'provisioning_status': 'ACTIVE'})
        if result.rowcount != 1:
            session.rollback()
            raise Exception(_('Unable to create pool in the '
                              'Octavia database.'))

        # Create Health Monitor
        hm_name = prefix + '-hm' + str(i)
        hm_id = uuidutils.generate_uuid()
        result = session.execute(
            "INSERT INTO health_monitor (id, project_id, pool_id, type, delay, "
            "timeout, fall_threshold, rise_threshold, http_method, url_path, "
            "expected_codes, enabled, provisioning_status, name, created_at, "
            "updated_at, operating_status) VALUES (:id, :project_id, :pool_id, "
            ":type, :delay, :timeout, :fall_threshold, :rise_threshold, "
            ":http_method, :url_path, :expected_codes, :enabled, "
            ":provisioning_status, :name, :created_at, :updated_at, "
            ":operating_status);",
            {'id': hm_id, 'project_id': PROJECT_ID, 'pool_id': pool_id,
             'type': 'HTTP', 'delay': 2, 'timeout': 1,
             'fall_threshold': 1, 'rise_threshold': 1,
             'http_method': 'GET', 'url_path': '/', 'expected_codes': '200',
             'enabled': True, 'provisioning_status': 'ACTIVE', 'name': hm_name,
             'operating_status': 'ONLINE',
             'created_at': datetime.datetime.utcnow(),
             'updated_at': datetime.datetime.utcnow()})
        if result.rowcount != 1:
            session.rollback()
            raise Exception(_('Unable to create health monitor in the '
                              'Octavia database.'))

        result = session.execute(
            "INSERT INTO session_persistence (pool_id, type, cookie_name, "
            "persistence_timeout, persistence_granularity) VALUES (:pool_id, "
            ":type, :cookie_name, :persistence_timeout, "
            ":persistence_granularity);",
            {'pool_id': pool_id, 'type': 'APP_COOKIE',
             'cookie_name': prefix + '-sp' + str(i),
             'persistence_timeout': None, 'persistence_granularity': None})

        hm = {'name': hm_name, 'id': hm_id}
        pool = {'name': name, 'id': pool_id, 'hm': hm}

        create_members(session, prefix, pool)

        pools.append(pool)
    listener['pools'] = pools

def create_l7rules(session, prefix, l7policy):

    l7rules = []

    for i in range(CONF.test_params.l7rules):
        l7rule_id = uuidutils.generate_uuid()
        l7rule = {'id': l7rule_id}

        result = session.execute(
            "INSERT INTO l7rule (id, project_id, l7policy_id, type, "
            "compare_type, `key`, value, invert, provisioning_status, "
            "created_at, updated_at, enabled, operating_status) VALUES "
            "(:id, :project_id, :l7policy_id, :type, :compare_type, "
            ":key, :value, :invert, :provisioning_status, :created_at, "
            ":updated_at, :enabled, :operating_status);",
            {'id': l7rule_id, 'project_id': PROJECT_ID,
             'l7policy_id': l7policy['id'], 'type': 'PATH',
             'compare_type': 'STARTS_WITH', 'key': None,
             'value': prefix + '-l7rule' + str(i), 'invert': False,
             'provisioning_status': 'ACTIVE',
             'created_at': datetime.datetime.utcnow(),
             'updated_at': datetime.datetime.utcnow(),
             'enabled': True, 'operating_status': 'ONLINE'})

        if result.rowcount != 1:
            session.rollback()
            raise Exception(_('Unable to create l7rule in the '
                              'Octavia database.'))
        l7rules.append(l7rule)
    l7policy['l7rules'] = l7rules

def create_l7policies(session, prefix, listener):

    l7policies = []

    for i in range(CONF.test_params.l7policies):
        name = prefix + '-l7policy' + str(i)
        l7policy_id = uuidutils.generate_uuid()
        l7policy = {'id': l7policy_id, 'name': name}

        result = session.execute(
            "INSERT INTO l7policy (id, project_id, name, description, "
            "listener_id, action, redirect_pool_id, redirect_url, position, "
            "enabled, provisioning_status, created_at, updated_at, "
            "operating_status) VALUES (:id, :project_id, :name, :description, "
            ":listener_id, :action, :redirect_pool_id, :redirect_url, "
            ":position, :enabled, :provisioning_status, :created_at, "
            ":updated_at, :operating_status);", 
            {'id': l7policy_id, 'project_id': PROJECT_ID, 'name': name,
             'description': 'A l7policy description',
             'listener_id': listener['id'], 'action': 'REDIRECT_TO_URL',
             'redirect_pool_id': None,
             'redirect_url': 'http://www.example.com/l7policy' + str(i),
             'position': i, 'enabled': True, 'provisioning_status': 'ACTIVE',
             'created_at': datetime.datetime.utcnow(),
             'updated_at': datetime.datetime.utcnow(),
             'operating_status': 'ONLINE'})

        if result.rowcount != 1:
            session.rollback()
            raise Exception(_('Unable to create l7policy in the '
                              'Octavia database.'))
        create_l7rules(session, prefix, l7policy)
        l7policies.append(l7policy)
    listener['l7policies'] = l7policies


def create_listeners(session, prefix, lb):

    listeners = []

    for i in range(CONF.test_params.listeners):
        name = prefix + '-listener' + str(i)
        listener_id = uuidutils.generate_uuid()
        listener = {'name': name, 'id': listener_id}

        create_pools(session, prefix, lb, listener)

        result = session.execute(
            "INSERT INTO listener (id, project_id, name, description, "
            "protocol, protocol_port, connection_limit, "
            "load_balancer_id, tls_certificate_id, default_pool_id, "
            "provisioning_status, operating_status, enabled, "
            "created_at, updated_at, peer_port, insert_headers, "
            "timeout_client_data, timeout_member_connect, "
            "timeout_member_data, timeout_tcp_inspect) VALUES "
            "(:id, :project_id, :name, "
            ":description, :protocol, :protocol_port, "
            ":connection_limit, :load_balancer_id, "
            ":tls_certificate_id, :default_pool_id, "
            ":provisioning_status, :operating_status, :enabled, "
            ":created_at, :updated_at, :peer_port, :insert_headers, "
            ":timeout_client_data, :timeout_member_connect, "
            ":timeout_member_data, :timeout_tcp_inspect);",
            {'id': listener_id, 'project_id': PROJECT_ID,
            'name': name, 'description': 'A listener',
            'protocol': 'HTTP', 'protocol_port': i,
            'connection_limit': 1000000,
            'load_balancer_id': lb['id'],
            'tls_certificate_id': None,
            'default_pool_id': listener['pools'][0]['id'],
            'provisioning_status': 'ACTIVE',
            'operating_status': 'ONLINE', 'enabled': True,
            'created_at': datetime.datetime.utcnow(),
            'updated_at': datetime.datetime.utcnow(),
            'peer_port': i, 'insert_headers': None,
            'timeout_client_data': 5000, 'timeout_member_connect': 5000,
            'timeout_member_data': 5000, 'timeout_tcp_inspect': 5000})
        if result.rowcount != 1:
            session.rollback()
            raise Exception(_('Unable to create listener in the '
                              'Octavia database.'))
        create_l7policies(session, prefix, listener)
        listeners.append(listener)
    lb['listeners'] = listeners


def setup_db(session_maker, prefix):

    session = session_maker(autocommit=False)

    lbs = []

    for i in range(CONF.test_params.load_balancers):
        name = prefix + '-lb' + str(i)
        lb_id = uuidutils.generate_uuid()
        lb = {'name': name, 'id': lb_id}

        # Create Load Balancer
        result = session.execute(
            "INSERT INTO load_balancer (id, project_id, name, "
            "description, provisioning_status, operating_status, enabled, "
            "created_at, updated_at, provider, topology, server_group_id) "
            "VALUES (:id, :project_id, "
            ":name, :description, :provisioning_status, "
            ":operating_status, :enabled, :created_at, :updated_at, "
            ":provider, :topology, :server_group_id);",
            {'id': lb_id, 'project_id': PROJECT_ID, 'name': name,
             'description': 'an lb', 'provisioning_status': 'ACTIVE',
             'operating_status': 'ONLINE', 'enabled': True,
             'created_at': datetime.datetime.utcnow(),
             'updated_at': datetime.datetime.utcnow(),
             'provider': 'amphora', 'topology': 'ACTIVE_STANDBY',
             'server_group_id': SERVER_GROUP_ID})
        if result.rowcount != 1:
            session.rollback()
            raise Exception(_('Unable to create load balancer in the '
                              'Octavia database.'))

        # Create VIP record
        result = session.execute(
            "INSERT INTO vip (load_balancer_id, ip_address, port_id, "
            "subnet_id, network_id, qos_policy_id, octavia_owned) VALUES "
            "(:lb_id, :ip_address, "
            ":port_id, :subnet_id, :network_id, :qos_policy_id, "
            ":octavia_owned);",
            {'lb_id': lb_id, 'ip_address': '203.0.113.10',
             'port_id': VIP_PORT_ID, 'subnet_id': VIP_SUBNET_ID,
             'network_id': VIP_NET_ID, 'qos_policy_id': PREFIX,
             'octavia_owned': True})
        if result.rowcount != 1:
            session.rollback()
            raise Exception(_('Unable to create VIP in the Octavia '
                              'database.'))

        # Create amphora records
        amp1_id = uuidutils.generate_uuid()
        result = session.execute(
            "INSERT INTO amphora (id, compute_id, status, load_balancer_id, "
            "lb_network_ip, vrrp_ip, ha_ip, vrrp_port_id, ha_port_id, role, "
            "cert_expiration, cert_busy, vrrp_interface, vrrp_id, "
            "vrrp_priority, cached_zone, created_at, updated_at, image_id) "
            "VALUES "
            "(:amp_id, :compute_id, :status, :load_balancer_id, "
            ":lb_network_ip, :vrrp_ip, :ha_ip, :vrrp_port_id, :ha_port_id, "
            ":role, :cert_expiration, :cert_busy, :vrrp_interface, :vrrp_id, "
            ":vrrp_priority, :cached_zone, :created_at, :updated_at, "
            ":image_id);",
            {'amp_id': amp1_id, 'compute_id': COMPUTE_ID, 'status': 'ACTIVE',
             'load_balancer_id': lb_id, 'lb_network_ip': '198.51.100.2',
             'vrrp_ip': '203.0.113.11', 'ha_ip': '203.0.113.10', 
             'vrrp_port_id': VRRP_PORT_ID, 'ha_port_id': VIP_PORT_ID,
             'role': 'MASTER', 'cert_expiration': datetime.datetime.utcnow(),
             'cert_busy': False, 'vrrp_interface': 'eth99', 'vrrp_id': 1,
             'vrrp_priority': 10, 'cached_zone': prefix,
             'created_at': datetime.datetime.utcnow(),
             'updated_at': datetime.datetime.utcnow(),
             'image_id': IMAGE_ID})
        if result.rowcount != 1:
            session.rollback()
            raise Exception(_('Unable to create amphora 1 in the Octavia '
                              'database.'))

        amp2_id = uuidutils.generate_uuid()
        result = session.execute(
            "INSERT INTO amphora (id, compute_id, status, load_balancer_id, "
            "lb_network_ip, vrrp_ip, ha_ip, vrrp_port_id, ha_port_id, role, "
            "cert_expiration, cert_busy, vrrp_interface, vrrp_id, "
            "vrrp_priority, cached_zone, created_at, updated_at, image_id) "
            "VALUES "
            "(:amp_id, :compute_id, :status, :load_balancer_id, "
            ":lb_network_ip, :vrrp_ip, :ha_ip, :vrrp_port_id, :ha_port_id, "
            ":role, :cert_expiration, :cert_busy, :vrrp_interface, :vrrp_id, "
            ":vrrp_priority, :cached_zone, :created_at, :updated_at, "
            ":image_id);",
            {'amp_id': amp2_id, 'compute_id': COMPUTE_ID, 'status': 'ACTIVE',
             'load_balancer_id': lb_id, 'lb_network_ip': '198.51.100.3',
             'vrrp_ip': '203.0.113.12', 'ha_ip': '203.0.113.10', 
             'vrrp_port_id': VRRP_PORT_ID, 'ha_port_id': VIP_PORT_ID,
             'role': 'BACKUP', 'cert_expiration': datetime.datetime.utcnow(),
             'cert_busy': False, 'vrrp_interface': 'eth99', 'vrrp_id': 1,
             'vrrp_priority': 10, 'cached_zone': prefix,
             'created_at': datetime.datetime.utcnow(),
             'updated_at': datetime.datetime.utcnow(),
             'image_id': IMAGE_ID})
        if result.rowcount != 1:
            session.rollback()
            raise Exception(_('Unable to create amphora 2 in the Octavia '
                              'database.'))

        lb['amphorae'] = [amp1_id, amp2_id]

        create_listeners(session, prefix, lb)

        lbs.append(lb)

    session.commit()
    return lbs

def cleanup_db(session_maker, prefix):

    session = session_maker(autocommit=False)

    result = session.execute(
        "DELETE FROM l7rule WHERE value LIKE '" + prefix + "-%';")
    result = session.execute(
        "DELETE FROM l7policy WHERE name LIKE '" + prefix + "-%';")
    # TODO(johnsom) delete from amphora_health with a join
    result = session.execute(
        "DELETE FROM health_monitor WHERE name LIKE '" + prefix + "-%';")
    result = session.execute(
        "DELETE FROM member WHERE name LIKE '" + prefix + "-%';")
    result = session.execute(
        "DELETE FROM session_persistence WHERE cookie_name LIKE '" +
        prefix + "-%';")
    # TODO(johnsom) delete from listener_statistics with a join
    result = session.execute(
        "DELETE FROM listener WHERE name LIKE '" + prefix + "-%';")
    result = session.execute(
        "DELETE FROM pool WHERE name LIKE '" + prefix + "-%';")
    result = session.execute(
        "DELETE FROM vip WHERE qos_policy_id = '" + prefix + "';")
    result = session.execute(
        "DELETE FROM amphora WHERE cached_zone = '" + prefix + "';")
    result = session.execute(
        "DELETE FROM load_balancer WHERE name LIKE '" + prefix + "-%';")

    session.commit()

def build_heartbeat_msg(amp_id, lb, seq):

    msg = None
    if CONF.health_manager.heartbeat_version:
        msg = {'id': amp_id, 'seq': seq,
               'ver': CONF.health_manager.heartbeat_version, 'listeners': {}}
    else:
        msg = {'id': amp_id, 'seq': seq, 'listeners': {}}

    for listener in lb['listeners']:

        pools = {}
        for pool in listener['pools']:
            pool_msg = {'status': 'UP', 'members': {}}
            for member in pool['members']:
                pool_msg['members'][member['id']] = 'UP'

            pools[pool['id']] = pool_msg

        listener_msg = {'status': 'OPEN', 'stats':
            {'rx': seq, 'ereq': seq, 'totconns': seq, 'tx': seq, 'conns': seq},
            'pools': pools}

        msg['listeners'][listener['id']] = listener_msg

    return msg

def amp_sim(exit_event, amp_id, lb):
    seq = 0
    sender = health_sender.UDPStatusSender()
    while not exit_event.is_set():
        sender.dosend(build_heartbeat_msg(amp_id, lb, seq))
        seq += 1
        time.sleep(CONF.health_manager.heartbeat_interval)

def main():
    logging.register_options(cfg.CONF)
    cfg.CONF(args=sys.argv[1:],
             project='stresshm',
             version='stresshm 1.0')
    logging.set_defaults()
    logging.setup(cfg.CONF, 'stresshm')
    LOG = logging.getLogger(__name__)

    octavia_context_manager = enginefacade.transaction_context()
    octavia_context_manager.configure(
        connection=CONF.test_params.octavia_db_connection)
    o_session_maker = octavia_context_manager.writer.get_sessionmaker()

    if CONF.db_create_only:
        LOG.info('Your run prefix ID is: %s' % PREFIX)
        setup_db(o_session_maker, PREFIX)
        return

    if CONF.clean_db:
        cleanup_db(o_session_maker, CONF.clean_db)
        return

    LOG.info('Your run prefix ID is: %s' % PREFIX)
    lbs = setup_db(o_session_maker, PREFIX)

    exit_event = multiprocessing.Event()
    processes = []

    for i in range(CONF.test_params.load_balancers):
        for amp_id in lbs[i]['amphorae']:
            amp = multiprocessing.Process(name='amp'+str(i), target=amp_sim,
                                          args=(exit_event, amp_id, lbs[i]))
            processes.append(amp)
            amp.start()

    time.sleep(CONF.test_params.test_runtime_secs)
    
    exit_event.set()

    for process in processes:
        process.join()

    cleanup_db(o_session_maker, PREFIX)

    return

if __name__ == "__main__":
    main()
