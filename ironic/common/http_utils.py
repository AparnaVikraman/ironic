import os

import jinja2
from oslo_config import cfg

from ironic.common import dhcp_factory
from ironic.common import exception
from ironic.common.i18n import _
from ironic.common import utils
from ironic.drivers.modules import deploy_utils
from ironic.drivers import utils as driver_utils
from ironic.openstack.common import fileutils
from ironic.openstack.common import log as logging


CONF = cfg.CONF

LOG = logging.getLogger(__name__)


def get_root_dir():
    """Returns the directory where the config files and images will live."""
    return CONF.http.http_root

def _ensure_config_dirs_exist(node_uuid):
    """Ensure that the node's  directory exist.

    :param node_uuid: the UUID of the node.

    """
    root_dir = get_root_dir()
    fileutils.ensure_tree(os.path.join(root_dir, node_uuid))


def get_deploy_kr_info(node_uuid, driver_info):
    """Get href and http path for deploy kernel and ramdisk.

    Note: driver_info should be validated outside of this method.
    """
    root_dir = get_root_dir()
    image_info = {}
    for label in ('deploy_kernel', 'deploy_ramdisk'):
        image_info[label] = (
            str(driver_info[label]),
            os.path.join(root_dir, node_uuid, label)
        )
    return image_info

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
    grub = '/'.join([CONF.http.http_url, uuid, 'grub.cfg'])
    bootfile = '/'.join([CONF.http.http_url, CONF.http.uefi_bootfile_name])
    return script.render({'uuid': uuid,
                          'kernel': http_options['deployment_aki_path'],
                          'ramdisk': http_options['deployment_ari_path'],
                          'grub': grub,
                          'uefi_bootfile': bootfile,
                          })

def _build_http_config(http_options, template):
    """Build the HTTP boot configuration file.

    This method builds the HTTP boot configuration file by rendering the
    template with the given parameters.

    :param http_options: A dict of values to set on the configuration file.
    :param template: The HTTP configuration template.
    :returns: A formatted string with the file content.

    """
    params = CONF.pxe.pxe_append_params
    kernel_params = ""
    for x in http_options:
        kernel_params += x+"=" +str(http_options[x])+" "
    tmpl_path, tmpl_file = os.path.split(template)
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(tmpl_path))
    template = env.get_template(tmpl_file)
    return template.render({'kernel_params': kernel_params,
                            'ROOT': '{{ ROOT }}',
                            'params': params,
                            'DISK_IDENTIFIER': '{{ DISK_IDENTIFIER }}',
                            })

def _link_ip_address_http_configs(task):
    """Link each IP address with the HTTP configuration file.

    :param task: A TaskManager instance.
    :raises: FailedToGetIPAddressOnPort
    :raises: InvalidIPv4Address

    """
    http_config_file_path = get_http_config_file_path(task.node.uuid)

    api = dhcp_factory.DHCPFactory().provider
    ip_addrs = api.get_ip_addresses(task)
    if not ip_addrs:
        raise exception.FailedToGetIPAddressOnPort(_(
            "Failed to get IP address for any port on node %s.") %
            task.node.uuid)
    for port_ip_address in ip_addrs:
        ip_address_path = _get_http_ip_address_path(port_ip_address)
        utils.unlink_without_raise(ip_address_path)
        utils.create_link_without_raise(http_config_file_path,
                                         ip_address_path)

def _get_http_ip_address_path(ip_address):
    """Convert an ipv4 address into a HTTP config file name.

    :param ip_address: A valid IPv4 address string in the format 'n.n.n.n'.
    :returns: the path to the config file.

    """
    ip = ip_address.split('.')
    hex_ip = '{0:02X}{1:02X}{2:02X}{3:02X}'.format(*map(int, ip))

    return os.path.join(
        CONF.http.http_root, hex_ip + ".conf"
    )

def create_http_boot_script(task, http_options, script=None):
    LOG.debug("Building HTTP startup script for node %s", task.node.uuid)

    if script is None:
        script = CONF.http.http_boot_script

    _ensure_config_dirs_exist(task.node.uuid)

    http_script_file_path = get_http_script_file_path(task.node.uuid)
    boot_script = _build_http_boot_script(task.node.uuid, script, http_options)
    utils.write_to_file(http_script_file_path, boot_script)


def create_http_config(task, http_options, template=None):
    """Generate HTTP configuration file and IP address links for it.

    This method will generate the HTTP configuration file for the task's
    node under a directory named with the UUID of that node. For each
    MAC address (port) of that node, a symlink for the configuration file
    will be created under the HTTP configuration directory, so regardless
    of which port boots first they'll get the same HTTP configuration.

    :param task: A TaskManager instance.
    :param http_options: A dictionary with the PXE configuration
    parameters.
    :param template: The HTTP configuration template. If no template is
    given the CONF.http.http_config_template will be used.

    """
    LOG.debug("Building http config for node %s", task.node.uuid)

    if template is None:
        template = CONF.http.http_config_template

    _ensure_config_dirs_exist(task.node.uuid)

    http_config_file_path = get_http_config_file_path(task.node.uuid)
    http_config = _build_http_config(http_options, template)
    utils.write_to_file(http_config_file_path, http_config)

    _link_ip_address_http_configs(task)

def clean_up_http_config(task):
    """Clean up the HTTP environment for the task's node.

    :param task: A TaskManager instance.

    """
    LOG.debug("Cleaning up HTTP config for node %s", task.node.uuid)

    api = dhcp_factory.DHCPFactory().provider
    ip_addresses = api.get_ip_addresses(task)
    if not ip_addresses:
        return

    for port_ip_address in ip_addresses:
        try:
            ip_address_path = _get_http_ip_address_path(port_ip_address)
        except exception.InvalidIPv4Address:
            continue
        utils.unlink_without_raise(ip_address_path)

    utils.rmtree_without_raise(os.path.join(get_root_dir(),
                                            task.node.uuid))

def dhcp_options_for_instance(task):
    """Retrieves the DHCP HTTP boot options.

    :param task: A TaskManager instance.
    """
    dhcp_opts = []
    script_name = os.path.basename(CONF.http.http_boot_script)
    http_script_url = '/'.join([CONF.http.http_url, script_name])

    dhcp_opts.append({'opt_name': 'bootfile-name',
                      'opt_value': http_script_url})

    dhcp_opts.append({'opt_name': 'server-ip-address',
                      'opt_value': CONF.http.http_server})
    dhcp_opts.append({'opt_name': 'http-server',
                      'opt_value': CONF.http.http_server})
    return dhcp_opts
