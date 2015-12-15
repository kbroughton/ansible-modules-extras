#!/usr/bin/python
#
# This is a free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This Ansible library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this library.  If not, see <http://www.gnu.org/licenses/>.

DOCUMENTATION = '''
---
module: ec2_eni
short_description: Create and optionally attach an Elastic Network Interface (ENI) to an instance
description:
    - Create and optionally attach an Elastic Network Interface (ENI) to an instance. If an ENI ID is provided, an attempt is made to update the existing ENI. By passing 'None' as the instance_id, an ENI can be detached from an instance.
version_added: "2.0"
author: Rob White, wimnat [at] gmail.com, @wimnat
options:
  eni_id:
    description:
      - The ID of the ENI
    required: false
    default: null
  filters:
    description:
      - Dictionary of key-value pairs that can be searched to locate eni_id if it is not known.
    required: false
    default: null
  instance_id:
    description:
      - Instance ID that you wish to attach ENI to. To detach an ENI from an instance, use 'None'.  To identify an existing attached eni, use filters attachment.instance-id instead.
    required: false
    default: null
  private_ip_address:
    description:
      - Private IP address.
    required: false
    default: null
  secondary_private_ip_address_count:
    version_added: "2.0"
    description:
      - Integer, add secondary private ip addresses to the eni_id interface (from the vpc subnet) so total = count.  Do nothing if count >= existing count.
    required: false
    default: null
  secondary_private_ip_addresses:
    version_added: "2.0"
    description:
      - add this list of secondary private ip addresses to the eni_id interface (from the vpc subnet).
    default: null
  subnet_id:
    description:
      - ID of subnet in which to create the ENI. Only required when state=present.
    required: true
  description:
    description:
      - Optional description of the ENI.
    required: false
    default: null
  security_groups:
    description:
      - List of security groups associated with the interface. Only used when state=present.
    required: false
    default: null
  state:
    description:
      - Create or delete ENI.
    required: false
    default: present
    choices: [ 'present', 'absent' ]
  device_index:
    description:
      - The index of the device for the network interface attachment on the instance.
    required: false
    default: 0
  force_detach:
    description:
      - Force detachment of the interface. This applies either when explicitly detaching the interface by setting instance_id to None or when deleting an interface with state=absent.
    required: false
    default: no
  delete_on_termination:
    description:
      - Delete the interface when the instance it is attached to is terminated. You can only specify this flag when the interface is being modified, not on creation.
    required: false
  source_dest_check:
    description:
      - By default, interfaces perform source/destination checks. NAT instances however need this check to be disabled. You can only specify this flag when the interface is being modified, not on creation.
    required: false
extends_documentation_fragment:
    - aws
    - ec2
'''

EXAMPLES = '''
# Note: These examples do not set authentication details, see the AWS Guide for details.

# Note, if you try to assign a secondary which is not available an error will occur:
# A client error (InvalidParameterValue) occurred when calling the AssignPrivateIpAddresses operation:
# [10.x.x.x] assigned, but move is not allowed.

# Create an ENI. As no security group is defined, ENI will be created in default security group
- ec2_eni:
    private_ip_address: 172.31.0.20
    subnet_id: subnet-xxxxxxxx
    state: present

# Create an ENI and attach it to an instance
- ec2_eni:
    instance_id: i-xxxxxxx
    device_index: 1
    private_ip_address: 172.31.0.20
    subnet_id: subnet-xxxxxxxx
    state: present

# Create an ENI with secondary ips generated and attached, and attach it to an instance
- ec2_eni:
    instance_id: i-xxxxxxx
    device_index: 1
    private_ip_address: 172.31.0.20
    secondary_private_ip_address_count: 3
    subnet_id: subnet-xxxxxxxx
    state: present

# Destroy an ENI, detaching it from any instance if necessary
- ec2_eni:
    eni_id: eni-xxxxxxx
    force_detach: yes
    state: absent

# Update an ENI
- ec2_eni:
    eni_id: eni-xxxxxxx
    description: "My new description"
    state: present

# Identify an insctance id by primary-ip-address and instance-id, then modify
# See here for allowed filters http://docs.aws.amazon.com/AWSEC2/latest/CommandLineReference/ApiReference-cmd-DescribeNetworkInterfaces.html
- ec2_eni:
    filters: '{ "attachment.instance-id": "i-1234fe78", "primary-ip-address": "10.0.1.2" }'
    subnet_id: subnet-xxxxxxxx
    secondary_private_ip_address_count: 2

# Update an ENI adding specified secondary_private_ip_addresses
- ec2_eni:
    eni_id: eni-xxxxxxx
    description: "My new description"
    state: present
    secondary_private_ip_addresses: [10.0.1.2,10.0.2.3]

# Detach an ENI from an instance
- ec2_eni:
    eni_id: eni-xxxxxxx
    instance_id: None
    state: present

### Delete an interface on termination
# First create the interface
- ec2_eni:
    instance_id: i-xxxxxxx
    device_index: 1
    private_ip_address: 172.31.0.20
    subnet_id: subnet-xxxxxxxx
    state: present
  register: eni

# Modify the interface to enable the delete_on_terminaton flag
- ec2_eni:
    eni_id: {{ "eni.interface.id" }}
    delete_on_termination: true

'''

import time
import xml.etree.ElementTree as ET
import re

try:
    import boto.ec2
    from boto.exception import BotoServerError
    HAS_BOTO = True
except ImportError:
    HAS_BOTO = False


def get_error_message(xml_string):

    root = ET.fromstring(xml_string)
    for message in root.findall('.//Message'):
        return message.text


def get_eni_info(interface):

    interface_info = {'id': interface.id,
                      'subnet_id': interface.subnet_id,
                      'vpc_id': interface.vpc_id,
                      'description': interface.description,
                      'owner_id': interface.owner_id,
                      'status': interface.status,
                      'mac_address': interface.mac_address,
                      'private_ip_address': interface.private_ip_address,
                      'secondary_private_ip_addresses': _get_secondary_private_ip_addresses(interface.private_ip_addresses),
                      'source_dest_check': interface.source_dest_check,
                      'groups': dict((group.id, group.name) for group in interface.groups),
                      }

    if interface.attachment is not None:
        interface_info['attachment'] = {'attachment_id': interface.attachment.id,
                                        'instance_id': interface.attachment.instance_id,
                                        'device_index': interface.attachment.device_index,
                                        'status': interface.attachment.status,
                                        'attach_time': interface.attachment.attach_time,
                                        'delete_on_termination': interface.attachment.delete_on_termination,
                                        }

    return interface_info

def wait_for_eni(eni, status):

    while True:
        time.sleep(3)
        eni.update()
        # If the status is detached we just need attachment to disappear
        if eni.attachment is None:
            if status == "detached":
                break
        else:
            if status == "attached" and eni.attachment.status == "attached":
                break


def create_eni(connection, module):

    instance_id = module.params.get("instance_id")
    if instance_id == 'None':
        instance_id = None
        do_detach = True
    else:
        do_detach = False
    device_index = module.params.get("device_index")
    subnet_id = module.params.get('subnet_id')
    private_ip_address = module.params.get('private_ip_address')
    secondary_private_ip_address_count = module.params.get('secondary_private_ip_address_count')
    secondary_private_ip_addresses = module.params.get('secondary_private_ip_addresses')

    description = module.params.get('description')
    security_groups = module.params.get('security_groups')
    changed = False

    try:
        eni = compare_eni(connection, module)
        if eni is None:
            eni = connection.create_network_interface(subnet_id,
                                                      private_ip_address,
                                                      description,
                                                      security_groups)
            connection.assign_private_ip_addresses(network_interface_id=eni.id,
                secondary_private_ip_address_count=secondary_private_ip_address_count,
                private_ip_addresses=secondary_private_ip_addresses,
                description=description, groups=security_groups)
            if instance_id is not None:
                try:
                    eni.attach(instance_id, device_index)
                except BotoServerError as ex:
                    eni.delete()
                    raise
            changed = True
            # Wait to allow creation / attachment to finish
            wait_for_eni(eni, "attached")
            eni.update()

    except BotoServerError as e:
        module.fail_json(msg=get_error_message(e.args[2]))

    module.exit_json(changed=changed, interface=get_eni_info(eni))


def _get_secondary_private_ip_addresses(private_ip_addresses_obj_list):
    # convert [PrivateIPAddress] to list of only non-primary ips
    results = []
    for item in private_ip_addresses_obj_list:
        if not item.primary:
            results.append(item.private_ip_address)
    return results

def modify_eni(connection, module):

    filters = module.params.get("filters")
    instance_id = module.params.get("instance_id")
    # Use instance_id to indicate attache/detatch, filters.attachment.instance-id to find eni attached to instance
    if instance_id == 'None':
        instance_id = None
        do_detach = True
    else:
        do_detach = False


    if filters:
        eni_result_set = connection.get_all_network_interfaces(filters=filters)
        if len(eni_result_set) > 1:
            mudule.fail_json(msg="Filters were not enough to specify unique eni_id, got {}".format(eni_result_set))
        elif len(eni_result_set) == 0:
            module.fail_json(msg="No eni found with specified filters")
        else:
            eni = eni_result_set[0]
            eni_id = eni.id
    else:
        eni_id = module.params.get("eni_id")
        # Get the eni with the eni_id specified
        eni_result_set = connection.get_all_network_interfaces(eni_id)
        eni = eni_result_set[0]

    device_index = module.params.get("device_index")
    subnet_id = module.params.get('subnet_id')
    private_ip_address = module.params.get('private_ip_address')
    secondary_private_ip_addresses = module.params.get('secondary_private_ip_addresses')
    if secondary_private_ip_addresses and not isinstance(secondary_private_ip_addresses, list):
        module.exit_json(msg="secondary_private_ip_addresses should be a python list")
    secondary_private_ip_address_count = module.params.get('secondary_private_ip_address_count')
    if secondary_private_ip_address_count and secondary_private_ip_address_count < 0:
        module.exit_json(msg="secondary_private_ip_address_count should be a positive integer, got {}".format(type(secondary_private_ip_address_count)))
    description = module.params.get('description')
    security_groups = module.params.get('security_groups')
    force_detach = module.params.get("force_detach")
    source_dest_check = module.params.get("source_dest_check")
    delete_on_termination = module.params.get("delete_on_termination")
    changed = False

    # fail if instance_id does not match attached eid
    if instance_id and (eni.attachment.instance_id != instance_id):
        module.fail_json(msg="Supplied instance_id is not consistent with the eni.attachment.instance_id.  Please detach first")

    try:
        if description is not None:
            if eni.description != description:
                connection.modify_network_interface_attribute(eni.id, "description", description)
                changed = True
        if security_groups is not None:
            if sorted(get_sec_group_list(eni.groups)) != sorted(security_groups):
                connection.modify_network_interface_attribute(eni.id, "groupSet", security_groups)
                changed = True
        if source_dest_check is not None:
            if eni.source_dest_check != source_dest_check:
                connection.modify_network_interface_attribute(eni.id, "sourceDestCheck", source_dest_check)
                changed = True
        if delete_on_termination is not None:
            if eni.attachment is not None:
                if eni.attachment.delete_on_termination is not delete_on_termination:
                    connection.modify_network_interface_attribute(eni.id, "deleteOnTermination", delete_on_termination, eni.attachment.id)
                    changed = True
            else:
                module.fail_json(msg="Can not modify delete_on_termination as the interface is not attached")

        if secondary_private_ip_addresses is not None:
            if set(_get_secondary_private_ip_addresses(eni.private_ip_addresses)) != set(secondary_private_ip_addresses):
                connection.assign_private_ip_addresses(network_interface_id=eni.id, private_ip_addresses=secondary_private_ip_addresses)
                changed = True
        if secondary_private_ip_address_count:
            # + 1 because primary_ip is in eni.private_ip_addresses
            diff = secondary_private_ip_address_count + 1 - len(eni.private_ip_addresses)
            if  diff > 0:
                connection.assign_private_ip_addresses(eni.id, secondary_private_ip_address_count=diff)
                changed = True
        if eni.attachment is not None and instance_id is None and do_detach is True:
            eni.detach(force_detach)
            wait_for_eni(eni, "detached")
            changed = True
        else:
            if instance_id is not None and eni.attachment is None:
                eni.attach(instance_id, device_index)
                wait_for_eni(eni, "attached")
                changed = True

    except BotoServerError as e:
        print e
        module.fail_json(msg=get_error_message(e.args[2]))

    eni.update()
    module.exit_json(changed=changed, interface=get_eni_info(eni))


def delete_eni(connection, module):

    eni_id = module.params.get("eni_id")
    force_detach = module.params.get("force_detach")

    try:
        eni_result_set = connection.get_all_network_interfaces(eni_id)
        eni = eni_result_set[0]

        if force_detach is True:
            if eni.attachment is not None:
                eni.detach(force_detach)
                # Wait to allow detachment to finish
                wait_for_eni(eni, "detached")
                eni.update()
            eni.delete()
            changed = True
        else:
            eni.delete()
            changed = True

        module.exit_json(changed=changed)
    except BotoServerError as e:
        msg = get_error_message(e.args[2])
        regex = re.compile('The networkInterface ID \'.*\' does not exist')
        if regex.search(msg) is not None:
            module.exit_json(changed=False)
        else:
            module.fail_json(msg=get_error_message(e.args[2]))

def compare_eni(connection, module):

    eni_id = module.params.get("eni_id")
    subnet_id = module.params.get('subnet_id')
    private_ip_address = module.params.get('private_ip_address')
    description = module.params.get('description')
    security_groups = module.params.get('security_groups')

    try:
        all_eni = connection.get_all_network_interfaces(eni_id)

        for eni in all_eni:
            remote_security_groups = get_sec_group_list(eni.groups)
            if ((eni.subnet_id == subnet_id) and
               (eni.private_ip_address == private_ip_address) and
               ((set(eni.private_ip_addresses) == set(secondary_private_ip_addresses)) or
                (len(eni.private_ip_addresses) >= secondary_private_ip_address_count)) and
               (eni.description == description) and
               (remote_security_groups == security_groups)):
                return eni
    except BotoServerError as e:
        module.fail_json(msg=get_error_message(e.args[2]))
    return None

def get_sec_group_list(groups):

    # Build list of remote security groups
    remote_security_groups = []
    for group in groups:
        remote_security_groups.append(group.id.encode())

    return remote_security_groups


def main():
    argument_spec = ec2_argument_spec()
    argument_spec.update(
        dict(
            eni_id = dict(default=None),
            filters = dict(),
            instance_id = dict(default=None),
            private_ip_address = dict(),
            secondary_private_ip_addresses = dict(default=None, type='list'),
            secondary_private_ip_address_count = dict(default=None, type='int'),
            subnet_id = dict(),
            description = dict(),
            security_groups = dict(type='list'),
            device_index = dict(default=0, type='int'),
            state = dict(default='present', choices=['present', 'absent']),
            force_detach = dict(default='no', type='bool'),
            source_dest_check = dict(default=None, type='bool'),
            delete_on_termination = dict(default=None, type='bool')
        )
    )

    module = AnsibleModule(argument_spec=argument_spec,
                           mutually_exclusive = [
                              ['secondary_private_ip_addresses', 'secondary_private_ip_address_count'],
                              ['eni_id', 'filters']
            ])
    if not HAS_BOTO:
        module.fail_json(msg='boto required for this module')

    region, ec2_url, aws_connect_params = get_aws_connection_info(module)

    if region:
        try:
            connection = connect_to_aws(boto.ec2, region, **aws_connect_params)
        except (boto.exception.NoAuthHandlerFound, AnsibleAWSError), e:
            module.fail_json(msg=str(e))
    else:
        module.fail_json(msg="region must be specified")

    state = module.params.get("state")
    eni_id = module.params.get("eni_id")
    filters = module.params.get("filters")

    if state == 'present':
        if eni_id or filters:
            modify_eni(connection, module)
        else:
            #  If neither eni_id or filters, create a new eni
            if module.params.get("subnet_id") is None:
                module.fail_json(msg="subnet_id must be specified when state=present")
            create_eni(connection, module)
    elif state == 'absent':
        if eni_id is None:
            module.fail_json(msg="eni_id must be specified")
        else:
            delete_eni(connection, module)

from ansible.module_utils.basic import *
from ansible.module_utils.ec2 import *

# this is magic, see lib/ansible/module_common.py
#<<INCLUDE_ANSIBLE_MODULE_COMMON>>

if __name__ == '__main__':
    main()
