# Deliberately insecure GCP IaC fixture. Do not apply.
terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "3.90.0"
    }
  }
}

resource "google_compute_firewall" "ssh_anywhere" {
  name    = "tg-fixture-ssh-anywhere"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  # tg-expect: IAC-060 | critical | public-ingress-admin-port | Firewall allows SSH from 0.0.0.0/0
  source_ranges = ["0.0.0.0/0"]
}

resource "google_storage_bucket" "exports" {
  name     = "tg-fixture-exports"
  location = "US"
  # tg-expect: IAC-061 | medium | storage-access-control | Uniform bucket-level access disabled
  uniform_bucket_level_access = false
}

resource "google_storage_bucket_iam_member" "public" {
  bucket = google_storage_bucket.exports.name
  role   = "roles/storage.objectViewer"
  # tg-expect: IAC-062 | critical | public-storage | Bucket readable by allUsers
  member = "allUsers"
}

resource "google_compute_instance" "worker" {
  name         = "tg-fixture-worker"
  machine_type = "e2-micro"
  zone         = "us-central1-a"
  # tg-expect: IAC-063 | medium | ip-forwarding | IP forwarding enabled on instance
  can_ip_forward = true

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
    }
  }

  network_interface {
    network = "default"
    # tg-expect: IAC-064 | medium | public-ip | Instance has a public IP (access_config)
    access_config {}
  }

  metadata = {
    # tg-expect: IAC-065 | medium | serial-port | Serial port access enabled
    serial-port-enable = "true"
  }
}

resource "google_sql_database_instance" "db" {
  name             = "tg-fixture-sql"
  database_version = "POSTGRES_14"
  region           = "us-central1"

  settings {
    tier = "db-f1-micro"

    ip_configuration {
      ipv4_enabled = true
      # tg-expect: IAC-066 | high | encryption-in-transit | Cloud SQL does not require SSL
      require_ssl = false

      authorized_networks {
        name = "everyone"
        # tg-expect: IAC-067 | critical | public-database | Cloud SQL authorized network 0.0.0.0/0
        value = "0.0.0.0/0"
      }
    }
  }
}

resource "google_container_cluster" "gke" {
  name               = "tg-fixture-gke"
  location           = "us-central1"
  initial_node_count = 1
  # tg-expect: IAC-068 | high | rbac-disabled | GKE legacy ABAC enabled
  enable_legacy_abac = true
}
