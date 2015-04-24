"""Testt class for HTTP driver."""

import os
import shutil
import six
import tempfile

import mock
from oslo_config import cfg
from oslo_serialization import jsonutils as json
from oslo_utils import fileutils

from ironic.common import boot_devices
from ironic.common import dhcp_factory
from ironic.common import exception
from ironic.common.glance_service import base_image_service
from ironic.common import states
from ironic.common import utils
from ironic.conductor import task_manager
from ironic.drivers.modules import deploy_utils
from ironic.drivers.modules import http
from ironic.drivers.modules.ilo import common as ilo_common
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

    @mock.patch.object(http, '_build_http_config', autospec=True)
    def _test_build_http_config_options(self, build_http_mock,
                                       whle_dsk_img=False):
        self.config(kernel_cmdline_params='test_param', group='deploy')
        self.config(api_url='http://192.168.122.184:6385', group='conductor')

        driver_internal_info = self.node.driver_internal_info
        driver_internal_info['is_whole_disk_image'] = whle_dsk_img
        self.node.driver_internal_info = driver_internal_info
        self.node.save()

        http_server = CONF.http.http_server

        http_url = 'http://192.1.2.3:1234'
        self.config(http_url=http_url, group='deploy')
        self.config(http_root='/httpboot', group='deploy')

        deploy_kernel = '/'.join([http_url, CONF.deploy.http_root,
                                     self.node.uuid, 'deploy_kernel'])
        deploy_ramdisk = '/'.join([http_url, CONF.deploy.http_root, 
                                      self.node.uuid, 'deploy_ramdisk'])
        kernel = '/'.join([http_url, CONF.deploy.http_root, 
                              self.node.uuid, 'kernel'])
        ramdisk = '/'.join([http_url, CONF.deploy.http_root,
                               self.node.uuid, 'ramdisk'])
        http_path = '/'.join([CONF.deploy.http_url, CONF.deploy.http_root])

        if whle_dsk_img:
            ramdisk = 'no_ramdisk'
            kernel = 'no_kernel'

        expected_options = {
            'ari_path': ramdisk,
            'deployment_ari_path': deploy_ramdisk,
            'kernel_cmdline_params': 'test_param',
            'aki_path': kernel,
            'deployment_aki_path': deploy_kernel,
            'http_server': http_server
        }

        image_info = {'deploy_kernel': ('deploy_kernel',
                                        os.path.join(http_path,
                                                     self.node.uuid,
                                                     'deploy_kernel')),
                      'deploy_ramdisk': ('deploy_ramdisk',
                                         os.path.join(http_path,
                                                      self.node.uuid,
                                                      'deploy_ramdisk')),
                      'kernel': ('kernel_id',
                                 os.path.join(http_path,
                                              self.node.uuid,
                                              'kernel')),
                      'ramdisk': ('ramdisk_id',
                                  os.path.join(http_path,
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

class HTTPUtilsMethodsTestCase(db_base.DbTestCase):

    def setUp(self):
        super(HTTPUtilsMethodsTestCase, self).setUp()
        n = {
            'driver': 'fake_http'
        }
        mgr_utils.mock_the_extension_manager(driver="fake_http")
        common_http_options = {
            'deployment_aki_path': u'http://192.168.122.184:9000//httpboot'
                                   u'/f9eaed3c-8ae0-4956-9592-c8a4fd327d18'
                                   u'/deploy_kernel',
            'aki_path': u'http://192.168.122.184:9000//httpboot/f9eaed3c-'
                        u'8ae0-4956-9592-c8a4fd327d18/kernel',
            'kernel_cmdline_params': 'test_param',
            'deployment_ari_path': u'http://192.168.122.184:9000//httpboot'
                                   u'/f9eaed3c-8ae0-4956-9592-c8a4fd327d18'
                                   u'/deploy_ramdisk',
            'root_device': 'vendor=fake,size=123',
            'ipa-api-url': 'http://192.168.122.184:6385',
        }
        self.http_options = {
            'deployment_key': '0123456789ABCDEFGHIJKLMNOPQRSTUV',
            'ari_path': u'http://192.168.122.184:9000//httpboot/f9eaed3c-'
                        u'8ae0-4956-9592-c8a4fd327d18/ramdisk',
            'iscsi_target_iqn': u'iqn-1be26c0b-03f2-4d2e-ae87-c02d7f33'
                                u'c123',
            'deployment_id': u'1be26c0b-03f2-4d2e-ae87-c02d7f33c123',
            'ironic_api_url': 'http://192.168.122.184:6385',
            'disk': 'cciss/c0d0,sda,hda,vda',
            'boot_option': 'netboot',
        }
        self.http_options.update(common_http_options)
        self.node = obj_utils.create_test_node(self.context, **n)


    def test_get_root_dir(self):
        expected_dir = '/httpboot'
        self.config(http_root=expected_dir, group='deploy')
        self.assertEqual(expected_dir, http.get_root_dir())

    def test__build_http_config(self):
        
        http_opts = self.http_options
        http_opts['boot_mode'] = 'uefi'
        
        rendered_template = http._build_http_config(
            self.http_options, CONF.http.http_config_template,
            '{{ ROOT }}', '{{ DISK_IDENTIFIER }}')
       
        expected_template = open(
            'ironic/tests/unit/drivers/grub.cfg').read().rstrip()

        self.assertEqual(six.text_type(expected_template), rendered_template)

    def test__build_http_boot_script(self):
        http_opts = self.http_options
        self.config(group='deploy', http_url='http://192.168.122.184:9000')
        self.config(group='deploy', http_root='/httpboot')
        uuid = 'f9eaed3c-8ae0-4956-9592-c8a4fd327d18'
        rendered_template = http._build_http_boot_script(uuid, 
                            CONF.http.http_boot_script, http_opts)
 
        expected_template = open(
            'ironic/tests/unit/drivers/startup.nsh'
        ).read().rstrip()

        self.assertEqual(six.text_type(expected_template), rendered_template)

    @mock.patch('ironic.common.utils.write_to_file', autospec=True)
    @mock.patch.object(http, '_build_http_config', autospec=True)
    @mock.patch.object(fileutils, 'ensure_tree', autospec=True)
    def test_create_http_config(self, ensure_tree_mock, build_mock,
                                          write_mock):
        build_mock.return_value = self.http_options
        with task_manager.acquire(self.context, self.node.uuid) as task:
            task.node.properties['capabilities'] = 'boot_mode:uefi'
            http.create_http_config(task, self.http_options,
                                        CONF.http.http_config_template)
            ensure_call = [
                mock.call(os.path.join(CONF.deploy.http_root, self.node.uuid))
            ]
            ensure_tree_mock.assert_has_calls(ensure_call)
	    build_mock.assert_called_with(self.http_options,
                                          CONF.http.http_config_template,
                                          '(( ROOT ))',
                                          '(( DISK_IDENTIFIER ))')
        http_cfg_file_path = http.get_http_config_file_path(self.node.uuid)
        write_mock.assert_called_with(http_cfg_file_path, self.http_options)

    @mock.patch('ironic.common.utils.write_to_file', autospec=True)
    @mock.patch.object(http, '_build_http_boot_script', autospec=True)
    @mock.patch.object(fileutils, 'ensure_tree', autospec=True)
    def test_create_http_boot_script(self, ensure_tree_mock, build_mock,
                                          write_mock):
        build_mock.return_value = self.http_options
        self.config(group='deploy', http_url='192.168.122.184:9000')
        self.config(group='deploy', http_root='/httpboot')
        with task_manager.acquire(self.context, self.node.uuid) as task:
            task.node.properties['capabilities'] = 'boot_mode:uefi'
            http.create_http_boot_script(task, self.http_options,
                                        CONF.http.http_boot_script)
            ensure_call = [
                mock.call(os.path.join(CONF.deploy.http_root, self.node.uuid))
            ]
            ensure_tree_mock.assert_has_calls(ensure_call)
            build_mock.assert_called_with(self.node.uuid,
                                          CONF.http.http_boot_script,
                                          self.http_options)
        http_script_file_path = http.get_http_script_file_path(self.node.uuid)
        write_mock.assert_called_with(http_script_file_path, self.http_options)

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

    @mock.patch.object(utils, 'rmtree_without_raise', autospec=True)
    def test_clean_up_http_config(self, mock_rmtree):
        root_id = os.path.join(CONF.deploy.http_root, self.node.uuid)
        with task_manager.acquire(self.context, self.node.uuid, 
                                  shared=True) as task:
            http.clean_up_http_config(task)
            mock_rmtree.assert_called_once_with(root_id)
 
    @mock.patch.object(utils, 'unlink_without_raise', autospec=True)
    @mock.patch.object(http, 'clean_up_http_config', autospec=True)
    @mock.patch.object(http, 'HTTPImageCache', autospec=True)
    def test__clean_up_http_env(self, mock_cache, mock_http_clean,
                                mock_unlink):
        image_info = {'label': ['', 'deploy_kernel']}
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            http._clean_up_http_env(task, image_info)
            mock_http_clean.assert_called_once_with(task)
            mock_unlink.assert_any_call('deploy_kernel')
        mock_cache.return_value.clean_up.assert_called_once_with()  

class HTTPBootTestCase(db_base.DbTestCase):

    def setUp(self):
        super(HTTPBootTestCase, self).setUp()
        self.context.auth_token = 'fake'
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
        self.config(group='deploy', http_url='http://1.2.3.4:5678')
        self.config(group='deploy', http_root='/httproot')
        mock_glance.return_value = {'properties': {'kernel_id': 'fake-kernel',
                                                   'ramdisk_id': 'fake-initr'}}
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            task.driver.boot.validate(task)

    @mock.patch.object(base_image_service.BaseImageService, '_show',
                       autospec=True)
    def test_validate_good_whole_disk_image(self, mock_glance):
        self.config(group='deploy', http_url='http://1.2.3.4:5678')
        self.config(group='deploy', http_root='/httproot')
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

    @mock.patch.object(ilo_common, 'get_ilo_object', autospec=True)
    @mock.patch.object(deploy_utils, 'get_instance_image_info', autospec=True)
    @mock.patch.object(http, '_get_deploy_image_info', autospec=True)
    @mock.patch.object(http, '_cache_ramdisk_kernel', autospec=True)
    @mock.patch.object(http, '_build_http_config_options', autospec=True)
    @mock.patch.object(http, 'create_http_config', autospec=True)
    @mock.patch.object(http, 'create_http_boot_script', autospec=True)
    @mock.patch.object(shutil, 'copyfile', autospec=True)
    def _test_prepare_ramdisk(self,copyfile_mock, mock_http_script,
                              mock_http_config, mock_build_http, 
                              mock_cache_r_k, mock_deploy_img_info,
                              mock_instance_img_info, ilo_object_mock, 
                              cleaning=False):
        self.config(group='deploy', http_url='http://myserver')
        mock_build_http.return_value = {}
        mock_deploy_img_info.return_value = {'deploy_kernel': 'a'}
        mock_instance_img_info.return_value = {'kernel': 'b'}
        mock_http_config.return_value = None
        mock_http_script.return_valure = '/uuid/startup.nsh'
        mock_cache_r_k.return_value = None
        ilo_object= ilo_object_mock.return_value
        with task_manager.acquire(self.context, self.node.uuid) as task:
            task.driver.boot.prepare_ramdisk(task, {'foo': 'bar'})
            mock_deploy_img_info.assert_called_once_with(task.node)
            if cleaning is False:
                mock_cache_r_k.assert_called_once_with(
                    self.context, task.node,
                    {'deploy_kernel': 'a', 'kernel': 'b'})
                mock_instance_img_info.assert_called_once_with(
                    task.node, self.context,
                    CONF.deploy.http_root)
            else:
                mock_cache_r_k.assert_called_once_with(
                    self.context, task.node,
                    {'deploy_kernel': 'a'})

            copyfile_mock.assert_called_once_with(
                    CONF.http.uefi_bootfile_name,
                    os.path.join(
                        CONF.deploy.http_root,
                        os.path.basename(CONF.http.uefi_bootfile_name)))
            mock_http_config.assert_called_once_with(
                task, {'foo': 'bar'}, CONF.http.http_config_template)

    def test_prepare_ramdisk(self):
        self.node.provision_state = states.DEPLOYING
        self.node.save()
        self._test_prepare_ramdisk()

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
    @mock.patch.object(http, 'switch_http_boot_script', autospec=True)
    @mock.patch.object(http, '_build_http_config_options', autospec=True)
    def test_prepare_instance_netboot(
            self, mock_build_http, switch_http_boot_script_mock,
            cache_mock, switch_http_config_mock, set_boot_device_mock, 
           get_image_info_mock):
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
                task.node, task.context, CONF.deploy.http_root)
            cache_mock.assert_called_once_with(
                task.context, task.node, image_info)
            switch_http_config_mock.assert_called_once_with(
                http_config_path, "30212642-09d3-467f-8e09-21685826ab50")
            http_boot_script = http.get_http_script_file_path(self.node.uuid)
            http_options = mock_build_http.return_value
            switch_http_boot_script_mock.assert_called_once_with(
                http_boot_script, http_options)
            set_boot_device_mock.assert_called_once_with(task,
                boot_devices.UEFISHELL)
            #mock_build_http.assert_called_once_with(task, task.context)

    @mock.patch.object(deploy_utils, 'get_instance_image_info', autospec=True)
    @mock.patch.object(deploy_utils, 'try_set_boot_device', autospec=True)
    @mock.patch.object(http, 'switch_http_config', autospec=True)
    @mock.patch.object(http, '_cache_ramdisk_kernel', autospec=True)
    @mock.patch.object(http, 'switch_http_boot_script', autospec=True)
    @mock.patch.object(http, '_build_http_config_options', autospec=True)
    def test_prepare_instance_netboot_missing_root_id(
            self, mock_build_http, switch_http_boot_script_mock, 
            cache_mock, switch_http_config_mock, set_boot_device_mock, 
            get_image_info_mock):
        image_info = {'kernel': ('', '/path/to/kernel'),
                      'ramdisk': ('', '/path/to/ramdisk')}
        get_image_info_mock.return_value = image_info
        with task_manager.acquire(self.context, self.node.uuid) as task:
            task.node.properties['capabilities'] = 'boot_mode:uefi'
            task.node.driver_internal_info['is_whole_disk_image'] = False

            task.driver.boot.prepare_instance(task)

            get_image_info_mock.assert_called_once_with(
                task.node, task.context, CONF.deploy.http_root)
            cache_mock.assert_called_once_with(
                task.context, task.node, image_info)
            self.assertFalse(mock_build_http.called)
            self.assertFalse(switch_http_config_mock.called)
            self.assertFalse(set_boot_device_mock.called)

    @mock.patch.object(deploy_utils, 'get_instance_image_info', autospec=True)
    @mock.patch.object(http, '_clean_up_http_env', autospec=True)
    def test_clean_up_instance(self, clean_up_http_env_mock,
                                     get_image_info_mock):
        with task_manager.acquire(self.context, self.node.uuid) as task:
            image_info = {'kernel': ['', '/path/to/kernel'],
                          'ramdisk': ['', '/path/to/ramdisk']}
            get_image_info_mock.return_value = image_info
            task.driver.boot.clean_up_instance(task)
            clean_up_http_env_mock.assert_called_once_with(task, image_info)
            get_image_info_mock.assert_called_once_with(
                task.node, task.context, CONF.deploy.http_root)
