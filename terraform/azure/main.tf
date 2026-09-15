# Deliberately insecure Azure IaC fixture (azurerm 2.x syntax). Do not apply.
terraform {
  required_providers {
    azurerm = {
      source = "hashicorp/azurerm"
      # tg-expect: SCA-041 | medium | provider-outdated | Terraform azurerm provider pinned to 2.0.0 (outdated)
      version = "2.0.0"
    }
  }
}

provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "fixture" {
  name     = "tg-fixture-rg"
  location = "eastus"
}

resource "azurerm_storage_account" "data" {
  name                     = "tgfixturedata"
  resource_group_name      = azurerm_resource_group.fixture.name
  location                 = azurerm_resource_group.fixture.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  # tg-expect: IAC-050 | high | encryption-in-transit | Storage account allows plaintext HTTP
  enable_https_traffic_only = false
  # tg-expect: IAC-051 | high | weak-tls | Storage account minimum TLS 1.0
  min_tls_version = "TLS1_0"
  # tg-expect: IAC-052 | high | public-storage | Storage account allows public blob access
  allow_blob_public_access = true
}

resource "azurerm_network_security_group" "vm" {
  name                = "tg-fixture-nsg"
  location            = azurerm_resource_group.fixture.location
  resource_group_name = azurerm_resource_group.fixture.name

  security_rule {
    name                   = "ssh-anywhere"
    priority               = 100
    direction              = "Inbound"
    access                 = "Allow"
    protocol               = "Tcp"
    source_port_range      = "*"
    destination_port_range = "22"
    # tg-expect: IAC-053 | critical | public-ingress-admin-port | NSG allows SSH from any source
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

resource "azurerm_sql_server" "db" {
  name                = "tg-fixture-sql"
  resource_group_name = azurerm_resource_group.fixture.name
  location            = azurerm_resource_group.fixture.location
  version             = "12.0"
  administrator_login = "sqladmin"
  # tg-expect: SECRET-074 | critical | generic-password | Hard-coded Azure SQL administrator password
  administrator_login_password = "Pr0d-zpL6aPjyCi54iu!"
}

resource "azurerm_sql_firewall_rule" "all" {
  name                = "allow-all"
  resource_group_name = azurerm_resource_group.fixture.name
  server_name         = azurerm_sql_server.db.name
  # tg-expect: IAC-054 | critical | public-database | SQL firewall allows entire IPv4 range
  start_ip_address = "0.0.0.0"
  end_ip_address   = "255.255.255.255"
}

resource "azurerm_key_vault" "vault" {
  name                = "tg-fixture-kv"
  location            = azurerm_resource_group.fixture.location
  resource_group_name = azurerm_resource_group.fixture.name
  tenant_id           = "00000000-0000-0000-0000-000000000000"
  sku_name            = "standard"
  # tg-expect: IAC-055 | medium | key-protection | Key Vault purge protection disabled
  purge_protection_enabled = false
}

resource "azurerm_kubernetes_cluster" "aks" {
  name                = "tg-fixture-aks"
  location            = azurerm_resource_group.fixture.location
  resource_group_name = azurerm_resource_group.fixture.name
  dns_prefix          = "tgfixture"

  default_node_pool {
    name       = "default"
    node_count = 1
    vm_size    = "Standard_B2s"
  }

  identity {
    type = "SystemAssigned"
  }

  role_based_access_control {
    # tg-expect: IAC-056 | high | rbac-disabled | AKS RBAC disabled
    enabled = false
  }
}
