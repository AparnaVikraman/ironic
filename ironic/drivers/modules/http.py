# Copyright 2013 Hewlett-Packard Development Company, L.P.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
"""
HTTP Boot Interface
"""

import os
import shutil

import jinja2
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import fileutils

from ironic.common import boot_devices
from ironic.common import dhcp_factory
from ironic.common import exception
from ironic.common.glance_service import service_utils
from ironic.common.i18n import _
from ironic.common.i18n import _LE
from ironic.common.i18n import _LW
from ironic.common import image_service as service
from ironic.common import paths
from ironic.common import pxe_utils
from ironic.common import states
from ironic.common import utils
from ironic.drivers import base
from ironic.drivers.modules import agent
from ironic.drivers.modules import deploy_utils
from ironic.drivers.modules import image_cache
from ironic.drivers.modules.ilo import common as ilo_common
from ironic.drivers import utils as driver_utils


http_opts = [
    cfg.StrOpt('http_config_template',
               default=paths.basedir_def(
                   'drivers/modules/grub.cfg'),
               help=_('On ironic-conductor node, template file for HTTP '
                      'configuration.')),
    cfg.StrOpt('http_server',
               default='$my_ip',
               help=_("IP address of ironic-conductor node's TFTP server.")),
    cfg.StrOpt('http_master_path',
               default='/httpboot/master_images',
               help=_('On ironic-conductor node, directory where master HTTP '
                      'images are stored on disk.')),
    # NOTE(dekehn): Additional boot files options may be created in the event
    #  other architectures require different boot files.
    cfg.StrOpt('uefi_bootfile_name',
               default='grubnetx64.efi.signed',
               help=_('Bootfile DHCP parameter for UEFI boot mode.')),
    cfg.StrOpt('http_boot_script',
               default=paths.basedir_def(
                   'drivers/modules/startup.nsh'),
               help=_('On ironic-conductor node, the path to the main HTTP '
                      'script file.')),
]

LOG = logging.getLogger(__name__)

CONF = cfg.CONF
CONF.register_opts(http_opts, group='http')
CONF.import_opt('deploy_callback_timeout', 'ironic.conductor.manager',
                group='conductor')

REQUIRED_PROPERTIES = {
    'deploy_kernel': _("UUID (from Glance) of the deployment kernel. "
                       "Required."),
    'deploy_ramdisk': _("UUID (from Glance) of the ramdisk that is "
                        "mounted at boot time. Required."),
}
COMMON_PROPERTIES = REQUIRED_PROPERTIES

def get_root_dir():
    """Returns the directory where the config files and images will live."""
    return CONF.deploy.http_root

def get_http_config_file_path(node_uuid):
    """Generate the path for the node's HTTP configuration file.

    :param node_uuid: the UUID of the node.
    :returns: The path to the node's HTTP configuration file.

    """
    return os.path.join(get_root_dir(), node_uuid, 'grub.cfg')

def get_http_script_file_path(node_uuid):
    """Generate the path for the node's HTTP boot script file.

    :param node_uuid: the UUID of the node.
    :returns: The path to the node's HTTP boot script file file.

    """
    return os.path.join(get_root_dir(), node_uuid, 'startup.nsh')


def _ensure_config_dirs_exist(node_uuid):
    """Ensure that the node's and HTTP configuration directories exist.

    :param node_uuid: the UUID of the node.

    """
    root_dir = get_root_dir()
    fileutils.ensure_tree(os.path.join(root_dir, node_uuid))


def _build_http_config(http_options, template, root_tag, disk_ident_tag):
    """Build the HTTP boot configuration file.

    This method builds the HTTP boot configuration file by rendering the
    template with the given parameters.

    :param http_options: A dict of values to set on the configuration file.
    :param template: The HTTP configuration template.
    :param root_tag: Root tag used in the HTTP config file.
    :param disk_ident_tag: Disk identifier tag used in the HTTP config file.
    :returns: A formatted string with the file content.

    """
    params = CONF.deploy.pxe_append_params
    kernel_params = ""
    for x in http_options:
        kernel_params += x+"=" +str(http_options[x])+" "
    tmpl_path, tmpl_file = os.path.split(template)
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(tmpl_path))
    template = env.get_template(tmpl_file)
    import pdb
    pdb.set_trace()
    return template.render({'kernel_params': kernel_params,
                            'ROOT': root_tag,
                            'params': params,
                            'DISK_IDENTIFIER': disk_ident_tag,
                            })

def _build_http_boot_script(uuid, script, http_options):
    """Build the HTTP boot script file.

    This method builds the HTTP boot script file by rendering the
    script with the given parameters.

    :param uuid: the UUID of the node.
    :param script: The HTTP script file template.
    :returns: A formatted string with the file content.

    """
    tmpl_path, tmpl_file = os.path.split(script)
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(tmpl_path))
    script = env.get_template(tmpl_file)
    grub = '/'.join([CONF.deploy.http_url, CONF.deploy.http_root, uuid, 
                     'grub.cfg'])
    bootfile = '/'.join([CONF.deploy.http_url, CONF.deploy.http_root, CONF.http.uefi_bootfile_name])
    return script.render({'uuid': uuid,
                          'kernel': http_options['deployment_aki_path'],
                          'ramdisk': http_options['deployment_ari_path'],
                          'grub': grub,
                          'uefi_bootfile': bootfile,
                          })


def create_http_config(task, http_options, template=None):
    """Generate HTTP configuration file and IP address links for it.

    This method will generate the HTTP configuration file for the task's
    node under a directory named with the UUID of that node. For each
    MAC address (port) of that node, a symlink for the configuration file
    will be created under the HTTP configuration directory, so regardless
    of which port boots first they'll get the same HTTP configuration.

    :param task: A TaskManager instance.
    :param http_options: A dictionary with the HTTP configuration
    parameters.
    :param template: The HTTP configuration template. If no template is
    given the CONF.http.http_config_template will be used.

    """
    LOG.debug("Building http config for node %s", task.node.uuid)

    if template is None:
        template = CONF.http.http_config_template

    _ensure_config_dirs_exist(task.node.uuid)

    http_config_file_path = get_http_config_file_path(task.node.uuid)
    import pdb
    pdb.set_trace()
    http_config_root_tag = '(( ROOT ))'
    http_config_disk_ident = '(( DISK_IDENTIFIER ))'
    http_config = _build_http_config(http_options, template, 
                                     http_config_root_tag,
                                     http_config_disk_ident)
    utils.write_to_file(http_config_file_path, http_config)

def create_http_boot_script(task, http_options, script=None):
    LOG.debug("Building HTTP startup script for node %s", task.node.uuid)
    if script is None:
        script = CONF.http.http_boot_script

    _ensure_config_dirs_exist(task.node.uuid)

    http_script_file_path = get_http_script_file_path(task.node.uuid)
    boot_script = _build_http_boot_script(task.node.uuid, script, http_options)
    utils.write_to_file(http_script_file_path, boot_script)

    return http_script_file_path

def _parse_driver_info(node):
    """Gets the driver specific Node deployment info.

    This method validates whether the 'driver_info' property of the
    supplied node contains the required information for this driver to
    deploy images to the node.

    :param node: a single Node.
    :returns: A dict with the driver_info values.
    :raises: MissingParameterValue
    """
    info = node.driver_info
    d_info = {k: info.get(k) for k in ('deploy_kernel', 'deploy_ramdisk')}
    error_msg = _("Cannot validate HTTP bootloader. Some parameters were"
                  " missing in node's driver_info")
    deploy_utils.check_for_missing_params(d_info, error_msg)
    return d_info


def _parse_instance_info(node):
    """Gets the instance and driver specific Node deployment info.

    This method validates whether the 'instance_info' and 'driver_info'
    property of the supplied node contains the required information for
    this driver to deploy images to the node.

    :param node: a single Node.
    :returns: A dict with the instance_info and driver_info values.
    :raises: MissingParameterValue, image_source is missing in node's
        instance_info. Also raises same exception if kernel/ramdisk is
        missing in instance_info for non-glance images.
    """
    info = {}
    info['image_source'] = node.instance_info.get('image_source')

    is_whole_disk_image = node.driver_internal_info.get('is_whole_disk_image')
    if not is_whole_disk_image:
        if not service_utils.is_glance_image(info['image_source']):
            info['kernel'] = node.instance_info.get('kernel')
            info['ramdisk'] = node.instance_info.get('ramdisk')

    error_msg = _("Cannot validate HTTP bootloader. Some parameters were "
                  "missing in node's instance_info.")
    deploy_utils.check_for_missing_params(info, error_msg)

    return info


def _get_instance_image_info(node, ctx):
    """Generate the paths for TFTP files for instance related images.

    This method generates the paths for instance kernel and
    instance ramdisk. This method also updates the node, so caller should
    already have a non-shared lock on the node.

    :param node: a node object
    :param ctx: context
    :returns: a dictionary whose keys are the names of the images (kernel,
        ramdisk) and values are the absolute paths of them. If it's a whole
        disk image, it returns an empty dictionary.
    """
    image_info = {}
    if node.driver_internal_info.get('is_whole_disk_image'):
        return image_info

    root_dir = get_root_dir()
    i_info = node.instance_info
    labels = ('kernel', 'ramdisk')
    d_info = _parse_instance_info(node)
    if not (i_info.get('kernel') and i_info.get('ramdisk')):
        glance_service = service.GlanceImageService(version=1, context=ctx)
        iproperties = glance_service.show(d_info['image_source'])['properties']
        for label in labels:
            i_info[label] = str(iproperties[label + '_id'])
        node.instance_info = i_info
        node.save()

    for label in labels:
        image_info[label] = (
            i_info[label],
            os.path.join(root_dir, node.uuid, label)
        )

    return image_info


def _get_deploy_image_info(node):
    """Generate the paths for HTTP files for deploy images.

    This method generates the paths for the deploy kernel and
    deploy ramdisk.

    :param node: a node object
    :returns: a dictionary whose keys are the names of the images (
        deploy_kernel, deploy_ramdisk) and values are the absolute
        paths of them.
    :raises: MissingParameterValue, if deploy_kernel/deploy_ramdisk is
        missing in node's driver_info.
    """
    d_info = _parse_driver_info(node)
    return pxe_utils.get_deploy_kr_info(node.uuid, d_info, get_root_dir())


def _build_http_config_options(task, http_info):
    """Build the HTTP config options for a node

    This method builds the HTTP boot options for a node,
    given all the required parameters.

    The options should then be passed to http.create_http_config to
    create the actual config files.

    :param task: A TaskManager object
    :param http_info: a dict of values to set on the configuration file
    :returns: A dictionary of http options to be used in the http bootfile
        template.
    """
    node = task.node
    is_whole_disk_image = node.driver_internal_info.get('is_whole_disk_image')

    # These are dummy values to satisfy elilo.
    # image and initrd fields in elilo config cannot be blank.
    kernel = 'no_kernel'
    ramdisk = 'no_ramdisk'

   
    deploy_kernel = '/'.join([CONF.deploy.http_url, CONF.deploy.http_root, 
                              node.uuid, 'deploy_kernel'])
    deploy_ramdisk = '/'.join([CONF.deploy.http_url, CONF.deploy.http_root,
                               node.uuid, 'deploy_ramdisk'])
    if not is_whole_disk_image:
        kernel = '/'.join([CONF.deploy.http_url, CONF.deploy.http_root, 
                           node.uuid, 'kernel'])
        ramdisk = '/'.join([CONF.deploy.http_url, CONF.deploy.http_root,
                            node.uuid, 'ramdisk'])
               
    http_options = {
        'deployment_aki_path': deploy_kernel,
        'deployment_ari_path': deploy_ramdisk,
        'pxe_append_params': CONF.deploy.pxe_append_params,
        'http_server': CONF.http.http_server,
        'aki_path': kernel,
        'ari_path': ramdisk
    }

    return http_options


def validate_boot_option_for_uefi(node):
    """In uefi boot mode, validate if the boot option is compatible.

    This method raises exception if whole disk image being deployed
    in UEFI boot mode without 'boot_option' being set to 'local'.

    :param node: a single Node.
    :raises: InvalidParameterValue
    """
    boot_mode = deploy_utils.get_boot_mode_for_deploy(node)
    boot_option = deploy_utils.get_boot_option(node)
    if (boot_mode == 'uefi' and
            node.driver_internal_info.get('is_whole_disk_image') and
            boot_option != 'local'):
        LOG.error(_LE("Whole disk image with netboot is not supported in UEFI "
                      "boot mode."))
        raise exception.InvalidParameterValue(_(
            "Conflict: Whole disk image being used for deploy, but "
            "cannot be used with node %(node_uuid)s configured to use "
            "UEFI boot with netboot option") %
            {'node_uuid': node.uuid})


def validate_boot_parameters_for_trusted_boot(node):
    """Check if boot parameters are valid for trusted boot."""
    boot_mode = deploy_utils.get_boot_mode_for_deploy(node)
    boot_option = deploy_utils.get_boot_option(node)
    is_whole_disk_image = node.driver_internal_info.get('is_whole_disk_image')
    # 'is_whole_disk_image' is not supported by trusted boot, because there is
    # no Kernel/Ramdisk to measure at all.
    if (boot_mode != 'uefi' or
        is_whole_disk_image or
        boot_option != 'netboot'):
        msg = (_("Trusted boot is only supported in UEFI boot mode with "
                 "netboot and without whole_disk_image, but Node "
                 "%(node_uuid)s was configured with boot_mode: %(boot_mode)s, "
                 "boot_option: %(boot_option)s, is_whole_disk_image: "
                 "%(is_whole_disk_image)s: at least one of them is wrong, and "
                 "this can be caused by enable secure boot.") %
               {'node_uuid': node.uuid, 'boot_mode': boot_mode,
                'boot_option': boot_option,
                'is_whole_disk_image': is_whole_disk_image})
        LOG.error(msg)
        raise exception.InvalidParameterValue(msg)


@image_cache.cleanup(priority=25)
class HTTPImageCache(image_cache.ImageCache):
    def __init__(self):
        super(HTTPImageCache, self).__init__(
            CONF.http.http_master_path,
            # MiB -> B
            cache_size=CONF.pxe.image_cache_size * 1024 * 1024,
            # min -> sec
            cache_ttl=CONF.pxe.image_cache_ttl * 60)


def _cache_ramdisk_kernel(ctx, node, http_info):
    """Fetch the necessary kernels and ramdisks for the instance."""
    fileutils.ensure_tree(
        os.path.join(get_root_dir(), node.uuid))
    LOG.debug("Fetching necessary kernel and ramdisk for node %s",
              node.uuid)
    deploy_utils.fetch_images(ctx, HTTPImageCache(), list(http_info.values()),
                              CONF.force_raw_images)


def _clean_up_http_env(task, images_info):
    """Cleanup HTTP environment of all the images in images_info.

    Cleans up the HTTP environment for the mentioned images in
    images_info.

    :param task: a TaskManager object
    :param images_info: A dictionary of images whose keys are the image names
        to be cleaned up (kernel, ramdisk, etc) and values are a tuple of
        identifier and absolute path.
    """
    for label in images_info:
        path = images_info[label][1]
        utils.unlink_without_raise(path)

    #pxe_utils.clean_up_pxe_config(task)
    HTTPImageCache().clean_up()


class HTTPBoot(base.BootInterface):

    def get_properties(self):
        """Return the properties of the interface.

        :returns: dictionary of <property name>:<property description> entries.
        """
        return COMMON_PROPERTIES

    def validate(self, task):
        """Validate the HTTP-specific info for booting deploy/instance images.

        This method validates the HTTP-specific info for booting the
        ramdisk and instance on the node.  If invalid, raises an
        exception; otherwise returns None.

        :param task: a task from TaskManager.
        :returns: None
        :raises: InvalidParameterValue, if some parameters are invalid.
        :raises: MissingParameterValue, if some required parameters are
            missing.
        """
        node = task.node

        if not driver_utils.get_node_mac_addresses(task):
            raise exception.MissingParameterValue(
                _("Node %s does not have any port associated with it.")
                % node.uuid)

        # Get the boot_mode capability value.
        boot_mode = deploy_utils.get_boot_mode_for_deploy(node)

        if (not CONF.deploy.http_url or
            not CONF.deploy.http_root):
            raise exception.MissingParameterValue(_(
                "HTTP boot is enabled but no HTTP URL or HTTP "
                "root was specified."))
         
        if boot_mode == 'bios':
            LOG.error(_LE("BIOS boot mode is not supported with "
                          "HTTP boot enabled."))
            raise exception.InvalidParameterValue(_(
                "Conflict: HTTP is enabled, but cannot be used with node"
                "%(node_uuid)s configured to use UEFI boot") %
                {'node_uuid': node.uuid})

        validate_boot_option_for_uefi(node)

        # Check the trusted_boot capabilities value.
        deploy_utils.validate_capabilities(node)
        if deploy_utils.is_trusted_boot_requested(node):
            # Check if 'boot_option' and boot mode is compatible with
            # trusted boot.
            validate_boot_parameters_for_trusted_boot(node)

        _parse_driver_info(node)
        d_info = _parse_instance_info(node)
        if node.driver_internal_info.get('is_whole_disk_image'):
            props = []
        elif service_utils.is_glance_image(d_info['image_source']):
            props = ['kernel_id', 'ramdisk_id']
        else:
            props = ['kernel', 'ramdisk']
        deploy_utils.validate_image_properties(task.context, d_info, props)

    def prepare_ramdisk(self, task, ramdisk_params):
        """Prepares the boot of Ironic ramdisk using HTTP.

        This method prepares the boot of the deploy kernel/ramdisk after
        reading relevant information from the node's driver_info and
        instance_info.

        :param task: a task from TaskManager.
        :param ramdisk_params: the parameters to be passed to the ramdisk.
            http driver passes these parameters as kernel command-line
            arguments.
        :returns: None
        :raises: MissingParameterValue, if some information is missing in
            node's driver_info or instance_info.
        :raises: InvalidParameterValue, if some information provided is
            invalid.
        :raises: IronicException, if some power or set boot boot device
            operation failed on the node.
        """
        node = task.node

        # Copy the HTTP boot script to HTTP root directory
        boot_script = CONF.http.http_boot_script

        #dhcp_opts = pxe_utils.dhcp_options_for_instance(task)
        #provider = dhcp_factory.DHCPFactory()
        #provider.update_dhcp(task, dhcp_opts)

        http_info = _get_deploy_image_info(node)

        # NODE: Try to validate and fetch instance images only
        # if we are in DEPLOYING state.
        if node.provision_state == states.DEPLOYING:
            http_info.update(_get_instance_image_info(node, task.context))

        http_options = _build_http_config_options(task, http_info)
        http_options.update(ramdisk_params)
        
        boot_script_path = create_http_boot_script(task, http_options, boot_script)
        boot_url = '/'.join([CONF.deploy.http_url, boot_script_path])
        ilo_object = ilo_common.get_ilo_object(node)
        ilo_object.set_http_boot_url(boot_url)

        http_config_template = CONF.http.http_config_template

        create_http_config(task, http_options, http_config_template)
        deploy_utils.try_set_boot_device(task, boot_devices.UEFISHELL)

        # FIXME(lucasagomes): If it's local boot we should not cache
        # the image kernel and ramdisk (Or even require it).
        _cache_ramdisk_kernel(task.context, node, http_info)

    def clean_up_ramdisk(self, task):
        """Cleans up the boot of ironic ramdisk.

        This method cleans up the HTTP environment that was setup for booting
        the deploy ramdisk. It unlinks the deploy kernel/ramdisk in the node's
        directory in tftproot and removes it's HTTP config.

        :param task: a task from TaskManager.
        :returns: None
        """
        """ node = task.node
        try:
            images_info = _get_deploy_image_info(node)
        except exception.MissingParameterValue as e:
            LOG.warning(_LW('Could not get deploy image info '
                            'to clean up images for node %(node)s: %(err)s'),
                        {'node': node.uuid, 'err': e})
        else:
            _clean_up_http_env(task, images_info)"""

    def prepare_instance(self, task):
        """Prepares the boot of instance.

        This method prepares the boot of the instance after reading
        relevant information from the node's instance_info. In case of netboot,
        it updates the dhcp entries and switches the HTTP config. In case of
        localboot, it cleans up the HTTP config.

        :param task: a task from TaskManager.
        :returns: None
        """
        node = task.node
        boot_option = deploy_utils.get_boot_option(node)

        # Make sure that the instance kernel/ramdisk is cached.
        # This is for the takeover scenario for active nodes.
        instance_image_info = _get_instance_image_info(
            task.node, task.context)
        _cache_ramdisk_kernel(task.context, task.node, instance_image_info)

        # If it's going to HTTP boot we need to update the DHCP server
        dhcp_opts = pxe_utils.dhcp_options_for_instance(task)
        provider = dhcp_factory.DHCPFactory()
        provider.update_dhcp(task, dhcp_opts)

        iwdi = task.node.driver_internal_info.get('is_whole_disk_image')
        try:
            root_uuid = task.node.driver_internal_info[
                'root_uuid_or_disk_id'
            ]
        except KeyError:
            if not iwdi:
                LOG.warn(_LW("The UUID for the root partition can't be "
                             "found, unable to switch the http config from "
                             "deployment mode to service (boot) mode for "
                             "node %(node)s"), {"node": task.node.uuid})
            else:
                LOG.warn(_LW("The disk id for the whole disk image can't "
                             "be found, unable to switch the http config "
                             "from deployment mode to service (boot) mode "
                             "for node %(node)s"),
                         {"node": task.node.uuid})
        else:
            http_config_path = get_http_config_file_path(
                task.node.uuid)
            deploy_utils.switch_http_config(http_config_path, root_uuid)
            http_boot_script = get_http_script_file_path(node.uuid)
            http_options = _build_http_config_options(task, task.context)
            deploy_utils.switch_http_boot_script(http_boot_script, http_options)
            # In case boot mode changes from bios to uefi, boot device
            # order may get lost in some platforms. Better to re-apply
            # boot device.
            deploy_utils.try_set_boot_device(task, boot_devices.UEFISHELL)

    def clean_up_instance(self, task):
        """Cleans up the boot of instance.

        This method cleans up the environment that was setup for booting
        the instance. It unlinks the instance kernel/ramdisk in node's
        directory in tftproot and removes the HTTP config.

        :param task: a task from TaskManager.
        :returns: None
        """
        node = task.node
        try:
            images_info = _get_instance_image_info(node, task.context)
        except exception.MissingParameterValue as e:
            LOG.warning(_LW('Could not get instance image info '
                            'to clean up images for node %(node)s: %(err)s'),
                        {'node': node.uuid, 'err': e})
        else:
            _clean_up_http_env(task, images_info)
