package terraform.azure

import future.keywords.contains
import future.keywords.if
import future.keywords.in

deny_public_network_access[msg] {
    resource := input.resource.azurerm_mssql_server[_]
    resource.public_network_access_enabled == true
    msg = sprintf("SQL server %v: public network access enabled", [resource.name])
}

deny_no_encryption[msg] {
    resource := input.resource.azurerm_storage_account[_]
    not resource.blob_properties[0].encryption
    msg = sprintf("storage account %v: blob encryption not configured", [resource.name])
}

deny_no_encryption[msg] {
    resource := input.resource.azurerm_managed_disk[_]
    not resource.encryption_settings
    msg = sprintf("managed disk %v: encryption not configured", [resource.name])
}

deny_no_nsg[msg] {
    resource := input.resource.azurerm_subnet[_]
    not resource.network_security_group_id
    msg = sprintf("subnet %v: no NSG attached", [resource.name])
}

deny_vm_public_ip[msg] {
    resource := input.resource.azurerm_network_interface[_]
    resource.public_ip_address_id != null
    msg = sprintf("NIC %v: has public IP attached", [resource.name])
}

deny_any_to_any[msg] {
    resource := input.resource.azurerm_network_security_rule[_]
    resource.source_address_prefixes[_] == "*"
    resource.destination_address_prefixes[_] == "*"
    msg = sprintf("NSG rule %v: allows any-to-any traffic", [resource.name])
}
