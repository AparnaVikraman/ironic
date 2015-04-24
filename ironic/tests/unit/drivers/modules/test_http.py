"""Testt class for HTTP driver."""

import os
import shutil
import tempfile

import mock
from oslo_config import cfg
from oslo_serialization import jsonutils as json
from oslo_utils import fileutils

from ironic.common import boot_devices
from ironic.common import dhcp_factory
from ironic.common import exception
from ironic.common.glance_service import base_image_service
from ironic.common import pxe_utils
from ironic.common import states
from ironic.common import utils
from ironic.conductor import task_manager
from ironic.drivers.modules import deploy_utils
from ironic.drivers.modules import http
from ironic.tests.unit.conductor import mgr_utils
from ironic.tests.unit.db import base as db_base
from ironic.tests.unit.db import utils as db_utils
from ironic.tests.unit.objects import utils as obj_utils

CONF = cfg.CONF

INST_INFO_DICT = db_utils.get_test_pxe_instance_info()
DRV_INFO_DICT = db_utils.get_test_pxe_driver_info()
DRV_INTERNAL_INFO_DICT = db_utils.get_test_pxe_driver_internal_info()


class HTTPPrivateMethodsTestCase(db_base.DbTestCase):

    def setUp(self):
        super(HTTPPrivateMethodsTestCase, self).setUp()
        n = {
            'driver': 'fake_http',
            'instance_info': INST_INFO_DICT,
            'driver_info': DRV_INFO_DICT,
            'driver_internal_info': DRV_INTERNAL_INFO_DICT,
        }
        mgr_utils.mock_the_extension_manager(driver="fake_http")
        self.node = obj_utils.create_test_node(self.context, **n)

    def test__get_deploy_image_info(self):
        expected_info = {'deploy_ramdisk':
                         (DRV_INFO_DICT['deploy_ramdisk'],
                          os.path.join(CONF.deploy.http_root,
                                       self.node.uuid,
                                       'deploy_ramdisk')),
                         'deploy_kernel':
                         (DRV_INFO_DICT['deploy_kernel'],
                          os.path.join(CONF.deploy.http_root,
                                       self.node.uuid,
                                       'deploy_kernel'))}
        image_info = http._get_deploy_image_info(self.node)
        self.assertEqual(expected_info, image_info)

    def test__get_deploy_image_info_missing_deploy_kernel(self):
        del self.node.driver_info['deploy_kernel']
        self.assertRaises(exception.MissingParameterValue,
                          http._get_deploy_image_info, self.node)

    def test__get_deploy_image_info_deploy_ramdisk(self):
        del self.node.driver_info['deploy_ramdisk']
        self.assertRaises(exception.MissingParameterValue,
                          http._get_deploy_image_info, self.node)

    @mock.patch.object(pxe_utils, '_build_pxe_config', autospec=True)
    def _test_build_pxe_config_options(self, build_pxe_mock,
                                       whle_dsk_img=False):
        self.config(pxe_append_params='test_param', group='pxe')
        self.config(api_url='http://192.168.122.184:6385', group='conductor')
        #self.config(disk_devices='sda', group='pxe')

        driver_internal_info = self.node.driver_internal_info
        driver_internal_info['is_whole_disk_image'] = whle_dsk_img
        self.node.driver_internal_info = driver_internal_info
        self.node.save()

        http_server = CONF.http.http_server

        http_url = 'http://192.1.2.3:1234'
        self.config(http_url=http_url, group='deploy')

        deploy_kernel = os.path.join(http_url, self.node.uuid,
                                     'deploy_kernel')
        deploy_ramdisk = os.path.join(http_url, self.node.uuid,
                                      'deploy_ramdisk')
        kernel = os.path.join(http_url, self.node.uuid, 'kernel')
        ramdisk = os.path.join(http_url, self.node.uuid, 'ramdisk')
        root_dir = CONF.deploy.http_root

        if whle_dsk_img:
            ramdisk = 'no_ramdisk'
            kernel = 'no_kernel'

        expected_options = {
            'ari_path': ramdisk,
            'deployment_ari_path': deploy_ramdisk,
            'pxe_append_params': 'test_param',
            'aki_path': kernel,
            'deployment_aki_path': deploy_kernel,
            'http_server': http_server,
        }

        image_info = {'deploy_kernel': ('deploy_kernel',
                                        os.path.join(root_dir,
                                                     self.node.uuid,
                                                     'deploy_kernel')),
                      'deploy_ramdisk': ('deploy_ramdisk',
                                         os.path.join(root_dir,
                                                      self.node.uuid,
                                                      'deploy_ramdisk')),
                      'kernel': ('kernel_id',
                                 os.path.join(root_dir,
                                              self.node.uuid,
                                              'kernel')),
                      'ramdisk': ('ramdisk_id',
                                  os.path.join(root_dir,
                                               self.node.uuid,
                                               'ramdisk'))}

        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            options = http._build_http_config_options(task, image_info)
        self.assertEqual(expected_options, options)

    def test__build_http_config_options(self):
        self._test_build_http_config_options(whle_dsk_img=True)

    def test__build_http_config_options_without_is_whole_disk_image(self):
        del self.node.driver_internal_info['is_whole_disk_image']
        self.node.save()
        self._test_build_http_config_options(whle_dsk_img=False)

    @mock.patch.object(deploy_utils, 'fetch_images', autospec=True)
    def test__cache_http_images_master_path(self, mock_fetch_image):
        temp_dir = tempfile.mkdtemp()
        self.config(http_root=temp_dir, group='deploy')
        self.config(http_master_path=os.path.join(temp_dir,
                                                  'http_master_path'),
                    group='http')
        image_path = os.path.join(temp_dir, self.node.uuid,
                                  'deploy_kernel')
        image_info = {'deploy_kernel': ('deploy_kernel', image_path)}
        fileutils.ensure_tree(CONF.http.http_master_path)

        http._cache_ramdisk_kernel(None, self.node, image_info)

        mock_fetch_image.assert_called_once_with(None,
                                                 mock.ANY,
                                                 [('deploy_kernel',
                                                   image_path)],
                                                 True)

    @mock.patch.object(http, 'HTTPImageCache', lambda: None)
    @mock.patch.object(fileutils, 'ensure_tree', autospec=True)
    @mock.patch.object(deploy_utils, 'fetch_images', autospec=True)
    def test__cache_ramdisk_kernel(self, mock_fetch_image, mock_ensure_tree):
        fake_http_info = {'foo': 'bar'}
        expected_path = os.path.join(CONF.deploy.http_root, self.node.uuid)

        http._cache_ramdisk_kernel(self.context, self.node, fake_http_info)
        mock_ensure_tree.assert_called_with(expected_path)
        mock_fetch_image.assert_called_once_with(
            self.context, mock.ANY, list(fake_http_info.values()), True)

@mock.patch.object(utils, 'unlink_without_raise', autospec=True)
@mock.patch.object(utils, 'rmtree_without_raise', autospec=True)
@mock.patch.object(http, 'HTTPImageCache', autospec=True)
class CleanUpHTTPEnvTestCase(db_base.DbTestCase):
    def setUp(self):
        super(CleanUpHTTPEnvTestCase, self).setUp()
        mgr_utils.mock_the_extension_manager(driver="fake_http")
        instance_info = INST_INFO_DICT
        instance_info['deploy_key'] = 'fake-56789'
        self.node = obj_utils.create_test_node(
            self.context, driver='fake_http',
            instance_info=instance_info,
            driver_info=DRV_INFO_DICT,
            driver_internal_info=DRV_INTERNAL_INFO_DICT,
        )

    def test_clean_up_http_config(self, mock_rmtree):
        root_id = os.path.join(CONF.deploy.http_root, self.node.uuid)
        with task_manager.acquire(self.context, self.node.uuid, 
                                  shared=True) as task:
            http.clean_up_http_config(task)
            mock_rmtree.assert_called_once_with(root_id)
     
    def test__clean_up_http_env(self, mock_cache, mock_unlink):
        image_info = {'label': ['', 'deploy_kernel']}
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            pxe._clean_up_http_env(task, image_info)
            mock_pxe_clean.assert_called_once_with(task)
            mock_unlink.assert_any_call('deploy_kernel')
        mock_cache.return_value.clean_up.assert_called_once_with()

Class HTTPBootTestCase(db_base.DbTestCase):

    def setUp(self):
        super(HTTPBootTestCase, self).setUp()
        self.context.auth_token = 'fake'
        #self.temp_dir = tempfile.mkdtemp()
        #self.config(images_path=self.temp_dir, group='pxe')
        mgr_utils.mock_the_extension_manager(driver="fake_http")
        instance_info = INST_INFO_DICT
        instance_info['deploy_key'] = 'fake-56789'
        self.node = obj_utils.create_test_node(
            self.context,
            driver='fake_http',
            instance_info=instance_info,
            driver_info=DRV_INFO_DICT,
            driver_internal_info=DRV_INTERNAL_INFO_DICT)
        self.port = obj_utils.create_test_port(self.context,
                                               node_id=self.node.id)
        self.config(group='conductor', api_url='http://127.0.0.1:1234/')

    def test_get_properties(self):
        expected = http.COMMON_PROPERTIES
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            self.assertEqual(expected, task.driver.get_properties())

    @mock.patch.object(base_image_service.BaseImageService, '_show',
                       autospec=True)
    def test_validate_good(self, mock_glance):
        mock_glance.return_value = {'properties': {'kernel_id': 'fake-kernel',
                                                   'ramdisk_id': 'fake-initr'}}
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            task.driver.boot.validate(task)

    @mock.patch.object(base_image_service.BaseImageService, '_show',
                       autospec=True)
    def test_validate_good_whole_disk_image(self, mock_glance):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            task.node.driver_internal_info['is_whole_disk_image'] = True
            task.driver.boot.validate(task)

    def test_validate_fail_missing_deploy_kernel(self):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            del task.node.driver_info['deploy_kernel']
            self.assertRaises(exception.MissingParameterValue,
                              task.driver.boot.validate, task)

    def test_validate_fail_missing_deploy_ramdisk(self):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            del task.node.driver_info['deploy_ramdisk']
            self.assertRaises(exception.MissingParameterValue,
                              task.driver.boot.validate, task)

    def test_validate_fail_missing_image_source(self):
        info = dict(INST_INFO_DICT)
        del info['image_source']
        self.node.instance_info = json.dumps(info)
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            task.node['instance_info'] = json.dumps(info)
            self.assertRaises(exception.MissingParameterValue,
                              task.driver.boot.validate, task)
    
    def test_validate_fail_invalid_config_uefi_whole_disk_image(self):
        properties = {'capabilities': 'boot_mode:uefi,boot_option:netboot'}
        instance_info = {"boot_option": "netboot"}
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            task.node.properties = properties
            task.node.instance_info['capabilities'] = instance_info
            task.node.driver_internal_info['is_whole_disk_image'] = True
            self.assertRaises(exception.InvalidParameterValue,
                              task.driver.boot.validate, task)

    def test_validate_fail_no_port(self):
        new_node = obj_utils.create_test_node(
            self.context,
            uuid='aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
            driver='fake_http', instance_info=INST_INFO_DICT,
            driver_info=DRV_INFO_DICT)
        with task_manager.acquire(self.context, new_node.uuid,
                                  shared=True) as task:
            self.assertRaises(exception.MissingParameterValue,
                              task.driver.boot.validate, task)
    
    @mock.patch.object(base_image_service.BaseImageService, '_show',
                       autospec=True)
    def test_validate_fail_no_image_kernel_ramdisk_props(self, mock_glance):
        mock_glance.return_value = {'properties': {}}
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            self.assertRaises(exception.MissingParameterValue,
                              task.driver.boot.validate,
                              task)
    @mock.patch.object(base_image_service.BaseImageService, '_show',
                       autospec=True)
    def test_validate_fail_glance_conn_problem(self, mock_glance):
        exceptions = (exception.GlanceConnectionFailed('connection fail'),
                      exception.ImageNotAuthorized('not authorized'),
                      exception.Invalid('invalid'))
        mock_glance.side_effect = iter(exceptions)
        for exc in exceptions:
            with task_manager.acquire(self.context, self.node.uuid,
                                      shared=True) as task:
                self.assertRaises(exception.InvalidParameterValue,
                                  task.driver.boot.validate, task)

    @mock.patch.object(deploy_utils, 'get_instance_image_info', autospec=True)
    @mock.patch.object(http, '_get_deploy_image_info', autospec=True)
    @mock.patch.object(http, '_cache_ramdisk_kernel', autospec=True)
    @mock.patch.object(http, '_build_http_config_options', autospec=True)
    @mock.patch.object(http, 'create_http_config', autospec=True)
    @mock.patch.object(http, 'create_http_boot_script', autospec=True)
    def _test_prepare_ramdisk(self, mock_http_config, mock_http_script,
                              mock_build_http, mock_cache_r_k,
                              mock_deploy_img_info,
                              mock_instance_img_info,
                              cleaning=False):
        mock_build_http.return_value = {}
        mock_deploy_img_info.return_value = {'deploy_kernel': 'a'}
        mock_instance_img_info.return_value = {'kernel': 'b'}
        mock_http_config.return_value = None
        mock_http_script.return_valure = None
        mock_cache_r_k.return_value = None
        with task_manager.acquire(self.context, self.node.uuid) as task:
            task.driver.boot.prepare_ramdisk(task, {'foo': 'bar'})
            mock_deploy_img_info.assert_called_once_with(task.node)
            if cleaning is False:
                mock_cache_r_k.assert_called_once_with(
                    self.context, task.node,
                    {'deploy_kernel': 'a', 'kernel': 'b'})
                mock_instance_img_info.assert_called_once_with(task.node,
                                                               self.context)
            else:
                mock_cache_r_k.assert_called_once_with(
                    self.context, task.node,
                    {'deploy_kernel': 'a'})
            mock_pxe_config.assert_called_once_with(
                task, {'foo': 'bar'}, CONF.http.http_config_template

    def test_prepare_ramdisk(self):
        self.node.provision_state = states.DEPLOYING
        self.node.save()
        properties = self.node.properties
        properties['capabilities'] = 'boot_mode:uefi'
        self.node.properties = properties
        self.node.save()
        self._test_prepare_ramdisk()

    @mock.patch.object(shutil, 'copyfile', autospec=True)
    def test_prepare_ramdisk_uefi(self, copyfile_mock):
        self.node.provision_state = states.DEPLOYING
        self.node.save()
        self.config(group='deploy', http_url='http://myserver')
        self._test_prepare_ramdisk()
        copyfile_mock.assert_called_once_with(
            CONF.http.uefi_bootfile_name,
            os.path.join(
                CONF.deploy.http_root,
                os.path.basename(CONF.http.uefi_bootfile_name)))

    def test_prepare_ramdisk_cleaning(self):
        self.node.provision_state = states.CLEANING
        self.node.save()
        self._test_prepare_ramdisk(cleaning=True)

    @mock.patch.object(http, '_clean_up_http_env', autospec=True)
    @mock.patch.object(http, '_get_deploy_image_info', autospec=True)
    def test_clean_up_ramdisk(self, get_deploy_image_info_mock,
                              clean_up_http_env_mock):
        with task_manager.acquire(self.context, self.node.uuid) as task:
            image_info = {'deploy_kernel': ['', '/path/to/deploy_kernel'],
                          'deploy_ramdisk': ['', '/path/to/deploy_ramdisk']}
            get_deploy_image_info_mock.return_value = image_info
            task.driver.boot.clean_up_ramdisk(task)
            clean_up_http_env_mock.assert_called_once_with(task, image_info)
            get_deploy_image_info_mock.assert_called_once_with(task.node)

    @mock.patch.object(deploy_utils, 'get_instance_image_info', autospec=True)
    @mock.patch.object(deploy_utils, 'try_set_boot_device', autospec=True)
    @mock.patch.object(http, 'switch_http_config', autospec=True)
    @mock.patch.object(http, '_cache_ramdisk_kernel', autospec=True)
    @mock.patch_object(http, 'switch_http_boot_script', autospec=True)
    @mock.patch.object(http, '_build_http_config_options', autospec=True)
    def test_prepare_instance_netboot(
            self, get_image_info_mock, cache_mock,
            dhcp_factory_mock, switch_http_config_mock,
            set_boot_device_mock, mock_build_http 
            switch_http_boot_script_mock):
        mock_build_http.return_value = {}
        image_info = {'kernel': ('', '/path/to/kernel'),
                      'ramdisk': ('', '/path/to/ramdisk')}
        get_image_info_mock.return_value = image_info
        with task_manager.acquire(self.context, self.node.uuid) as task:
            http_config_path = http.get_http_config_file_path(
                task.node.uuid)
            task.node.properties['capabilities'] = 'boot_mode:uefi'
            task.node.driver_internal_info['root_uuid_or_disk_id'] = (
                "30212642-09d3-467f-8e09-21685826ab50")
            task.node.driver_internal_info['is_whole_disk_image'] = False

            task.driver.boot.prepare_instance(task)

            get_image_info_mock.assert_called_once_with(
                task.node, task.context)
            cache_mock.assert_called_once_with(
                task.context, task.node, image_info)
            switch_http_config_mock.assert_called_once_with(
                http_config_path, "30212642-09d3-467f-8e09-21685826ab50")
            http_boot_script = http.get_http_script_file_path(node.uuid)
            http_options = mock_build_http.return_value
            switch_http_boot_script_mock.assert_called_once_with(
                http_boot_script, http_options)
            set_boot_device_mock.assert_called_once_with(task,
                                                         boot_devices.UEFISHELL)

    @mock.patch.object(deploy_utils, 'get_instance_image_info', autospec=True)
    @mock.patch.object(deploy_utils, 'try_set_boot_device', autospec=True)
    @mock.patch.object(http, 'switch_http_config', autospec=True)
    @mock.patch.object(http, '_cache_ramdisk_kernel', autospec=True)
    @mock.patch_object(http, 'switch_http_boot_script', autospec=True)
    @mock.patch.object(http, '_build_http_config_options', autospec=True)
    def test_prepare_instance_netboot_missing_root_id(
            self, get_image_info_mock, cache_mock,
            dhcp_factory_mock, switch_http_config_mock,
            set_boot_device_mock, mock_build_http
            switch_http_boot_script_mock):
        mock_build_http.return_value = {}
        image_info = {'kernel': ('', '/path/to/kernel'),
                      'ramdisk': ('', '/path/to/ramdisk')}
        get_image_info_mock.return_value = image_info
        with task_manager.acquire(self.context, self.node.uuid) as task:
            task.node.properties['capabilities'] = 'boot_mode:uefi'
            task.node.driver_internal_info['root_uuid_or_disk_id'] = (
                "30212642-09d3-467f-8e09-21685826ab50")
            task.node.driver_internal_info['is_whole_disk_image'] = False

            task.driver.boot.prepare_instance(task)

            get_image_info_mock.assert_called_once_with(
                task.node, task.context)
            cache_mock.assert_called_once_with(
                task.context, task.node, image_info)
            self.assertFalse(switch_pxe_config_mock.called)
            self.assertFalse(set_boot_device_mock.called)

    @mock.patch.object(http, '_clean_up_http_env', autospec=True)
    @mock.patch.object(deploy_utils, 'get_instance_image_info', autospec=True)
    def test_clean_up_instance(self, get_image_info_mock,
                               clean_up_http_env_mock):
        with task_manager.acquire(self.context, self.node.uuid) as task:
            image_info = {'kernel': ['', '/path/to/kernel'],
                          'ramdisk': ['', '/path/to/ramdisk']}
            get_image_info_mock.return_value = image_info
            task.driver.boot.clean_up_instance(task)
            clean_up_http_env_mock.assert_called_once_with(task, image_info)
            get_image_info_mock.assert_called_once_with(
                task.node, task.context)
