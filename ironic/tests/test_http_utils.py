import os

import mock
from oslo_config import cfg

from ironic.common import http_utils
from ironic.conductor import task_manager
from ironic.tests.conductor import utils as mgr_utils
from ironic.tests.db import base as db_base
from ironic.tests.objects import utils as object_utils

CONF = cfg.CONF

class TestHTTPUtils(db_base.DbTestCase):

    def setUp(self):
        super(TestHTTPUtils, self).setUp()
        mgr_utils.mock_the_extension_manager(driver="fake")

        common_http_options = {
                'deployment_aki_path': 'http://1.2.3.4:1234/deploy_kernel',
                'aki_path': 'http://1.2.3.4:1234/kernel',
                'pxe_append_params': 'test_param',
                'deployment_ari_path': 'http://1.2.3.4:1234/deploy_ramdisk',
                'root_device': 'vendor=fake,size=123',
                'ipa-api-url': 'http://192.168.122.184:6385',
        }

        self.http_options = {
            'deployment_key': '0123456789ABCDEFGHIJKLMNOPQRSTUV',
            'ari_path': 'http://1.2.3.4:1234/ramdisk',
            'iscsi_target_iqn': u'iqn-0bf48343-368a-426d-ba70-c3655e019d79',
            'ironic_api_url': 'http://192.168.122.184:6385',
            'disk': 'cciss/c0d0,sda,hda,vda',
            'boot_option': 'netboot',
            -----'ipa-driver-name': 'pxe_ssh',
            'boot_mode': 'bios',
        }

        self.http_options.update(common_http_options)

        self.node = object_utils.create_test_node(self.context)

    def test_get_root_dir(self):
        expected_dir = '/httpboot'
        self.config(group='http')
        self.config(http_root=expected_dir, group='http')
        self.assertEqual(expected_dir, http_utils.get_root_dir())

    def _test_get_deploy_kr_info(self, expected_dir):
        node_uuid = 'fake-node'
        driver_info = {
            'deploy_kernel': 'glance://deploy-kernel',
            'deploy_ramdisk': 'glance://deploy-ramdisk',
        }

        expected = {
            'deploy_kernel': ('glance://deploy-kernel',
                              expected_dir + '/fake-node/deploy_kernel'),
            'deploy_ramdisk': ('glance://deploy-ramdisk',
                               expected_dir + '/fake-node/deploy_ramdisk'),
        }

        kr_info = http_utils.get_deploy_kr_info(node_uuid, driver_info)
        self.assertEqual(expected, kr_info)

    def test_get_deploy_kr_info(self):
        expected_dir = '/http'
        self.config(http_root=expected_dir, group='http')
        self._test_get_deploy_kr_info(expected_dir)

    def test_get_deploy_kr_info_bad_driver_info(self):
        self.config(tftp_root='/http', group='http')
        node_uuid = 'fake-node'
        driver_info = {}
        self.assertRaises(KeyError,
                          http_utils.get_deploy_kr_info,
                          node_uuid,
                          driver_info)

    def test_get_http_config_file_path(self):
        self.assertEqual(os.path.join(CONF.http.http_root,
                                      self.node.uuid,
                                      'grub.cfg'),
                         http_utils.get_http_config_file_path(self.node.uuid))

    def test_get_http_script_file_path(self):
        self.assertEqual(os.path.join(CONF.http.http_root,
                                      self.node.uuid,
                                      'startup.nsh'),
                         http_utils.get_http_script_file_path(self.node.uuid))

    def test__build_http_config(self):
        self.config(
            http_config_template='ironic/drivers/modules/grub.cfg',
            group='http'
        )
        self.config(http_url='http://1.2.3.4:1234', group='http')
        rendered_template = http_utils._build_http_config(
                self.http_options, CONF.http.http_config_template)

        expected_template = open(
            'ironic/tests/drivers/grub.cfg').read().rstrip()

        self.assertEqual(unicode(expected_template), rendered_template)

    def test__build_http_boot_script(self):
        self.config(
            http_config_template='ironic/drivers/modules/startup.nsh',
            group='http'
        )
        self.config(http_url='http://1.2.3.4:1234', group='http')
        node_uuid = 'fake-node'
        rendered_template = http_utils._build_http_boot_script(
                node_uuid, CONF.http.http_boot_script, self.http_options)

        expected_template = open(
            'ironic/tests/drivers/startup.nsh').read().rstrip()

        self.assertEqual(unicode(expected_template), rendered_template)

    @mock.patch('ironic.common.utils.write_to_file', autospec=True)
    @mock.patch.object(http_utils, '_build_http_config', autospec=True)
    @mock.patch('ironic.openstack.common.fileutils.ensure_tree', autospec=True)
    def test_create_http_config(self, ensure_tree_mock, build_mock, write_mock):
        build_mock.return_value = self.http_options
        with task_manager.acquire(self.context, self.node.uuid) as task:
            http_utils.create_http_config(task, self.http_options,
                                          CONF.http.http_config_template)
            build_mock.assert_called_with(self.http_options,
                                          CONF.http.http_config_template)

        ensure_calls = [
            mock.call(os.path.join(CONF.http.http_root, self.node.uuid)),
        ]
        ensure_tree_mock.assert_has_calls(ensure_calls)

        http_cfg_file_path = http_utils.get_http_config_file_path(self.node.uuid)
        write_mock.assert_called_with(http_cfg_file_path, self.http_options)

    @mock.patch('ironic.common.utils.write_to_file', autospec=True)
    @mock.patch.object(http_utils, '_build_http_boot_script', autospec=True)
    @mock.patch('ironic.openstack.common.fileutils.ensure_tree', autospec=True)
    def test_create_http_boot_script(self, ensure_tree_mock, build_mock,
                                     write_mock):
        build_mock.return_value = self.http_options
        node_uuid = 'fake-node'
        with task_manager.acquire(self.context, self.node.uuid) as task:
            http_utils.create_http_boot_script(task, self.http_options,
                                          CONF.http.http_boot_script)
            build_mock.assert_called_with(self.node_uuid,
                                          CONF.http.http_boot_script,
                                          self.http_options)

        ensure_calls = [
            mock.call(os.path.join(CONF.http.http_root, self.node.uuid)),
        ]
        ensure_tree_mock.assert_has_calls(ensure_calls)

        http_boot_file_path = http_utils.get_http_script_file_path(self.node.uuid)
        write_mock.assert_called_with(http_boot_file_path, self.http_options)

    @mock.patch('ironic.common.utils.rmtree_without_raise')
    @mock.patch('ironic.common.utils.unlink_without_raise')
    @mock.patch('ironic.common.dhcp_factory.DHCPFactory.provider')
    def test_clean_up_http_config(self, provider_mock, unlink_mock,
                                  rmtree_mock):
        ip_address = '10.10.0.1'
        address = "aa:aa:aa:aa:aa:aa"
        object_utils.create_test_port(self.context, node_id=self.node.id,
                                      address=address)

        provider_mock.get_ip_addresses.return_value = [ip_address]

        with task_manager.acquire(self.context, self.node.uuid) as task:
            http_utils.clean_up_http_config(task)

            unlink_mock.assert_called_once_with('/httpboot/0A0A0001.conf')
            rmtree_mock.assert_called_once_with(
                os.path.join(CONF.http.http_root, self.node.uuid))

    def test_dhcp_options_for_instance(self):
        self.config(http_server='10.10.1.1', group='http')
        self.config(http_bootfile_name='fake-bootfile', group='http')
        expected_info = [{'opt_name': 'bootfile-name',
                          'opt_value': 'fake-bootfile'},
                         {'opt_name': 'server-ip-address',
                          'opt_value': '10.10.1.1'},
                         {'opt_name': 'http-server',
                          'opt_value': '10.10.1.1'}
                        ]
        with task_manager.acquire(self.context, self.node.uuid) as task:
            self.assertEqual(expected_info,
                             http_utils.dhcp_options_for_instance(task))
