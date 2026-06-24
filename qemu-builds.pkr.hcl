packer {
  required_version = ">= 1.11.0"
  required_plugins {
    qemu = {
      version = ">= 1.1.0"
      source  = "github.com/hashicorp/qemu"
    }
    ansible = {
      version = ">= 1.1.2"
      source  = "github.com/hashicorp/ansible"
    }
  }
}

locals {
  build_time = "${formatdate("YYYYMMDD", timestamp())}.${var.build_number}"
}

build {
  name = "prep"
  dynamic "source" {
    for_each = { for src in var.prep : src.name => src }
    iterator = it
    labels   = ["qemu.enterprise_linux"]
    content {
      name             = it.value.name
      vm_name          = "${it.value.name}.qcow2"
      output_directory = "prep"

      # Boot directly from the Debian genericcloud qcow2 - no installer needed
      iso_url          = it.value.iso_path
      iso_checksum     = "sha256:${it.value.iso_checksum}"
      disk_image       = true
      use_backing_file = true

      # Cloud-init user-data to inject SSH key and configure root login
      cd_content = {
        "user-data" = templatefile(
          "${var.config_folder}/templates/debian/12/cloud-init.pkrtpl.hcl",
          {
            public_key = file("${var.config_folder}/.ssh/id_rsa.pub")
          }
        )
        "meta-data" = ""
      }
      cd_label = "cidata"
    }
  }

  provisioner "shell" {
    remote_folder = "/root"
    pause_after   = "20s"
    inline = [
      "date +%s > /tmp/prep_build.txt",
      "sleep 20",
      "sync",
    ]
  }

  post-processor "shell-local" {
    command = <<-CMD
      sha256sum ${build.name}/${source.name}.qcow2 | \
        cut -d' ' -f1 > ${build.name}/${source.name}.sha256
    CMD
  }
}

build {
  name = "post"
  dynamic "source" {
    for_each = { for idx, src in var.post : "${src.name}@${idx}" => src }
    iterator = it
    labels   = ["qemu.enterprise_linux"]
    content {
      name             = "${it.value.name}@${it.value.target}"
      vm_name          = "${it.value.name}@${it.value.target}.qcow2"
      iso_url          = "prep/${it.value.name}.qcow2"
      iso_checksum     = "sha256:${chomp(file("prep/${it.value.name}.sha256"))}"
      disk_image       = true
      use_backing_file = true
      output_directory = "post"
    }
  }

  provisioner "ansible" {
    user                 = "root"
    playbook_file        = "ansible/site.yml"
    timeout              = "2h" # Good addition! Keep this.
    roles_path           = "packer_cache/ansible/roles/${source.name}"
    collections_path     = "packer_cache/ansible/collections/${source.name}"
    galaxy_force_install = true
    galaxy_command       = "bin/ansible-galaxy.sh"
    galaxy_file          = fileexists("ansible/requirements.yml") ? "ansible/requirements.yml" : null
    ansible_env_vars = [
      "ANSIBLE_ROLES_PATH=${var.pwd}/packer_cache/ansible/roles/${source.name}",
      "ANSIBLE_COLLECTIONS_PATHS=~/.ansible/collections:/usr/share/ansible/collections:${var.pwd}/packer_cache/ansible/collections/${source.name}",
      
      # FIX 1: Instructs Ansible to skip the rapid file purge commands over SSH 
      # immediately following a heavy task. Keeps the files on the guest temporarily.
      "ANSIBLE_KEEP_REMOTE_FILES=1",
      
      # FIX 2: Prevents Ansible from cycling multiplexed socket connections 
      # back-to-back while QEMU 1.7.x processes the time drift.
      "ANSIBLE_SSH_ARGS=-o ControlMaster=auto -o ControlPersist=2h -o ControlPath=/tmp/ansible-ssh-%h-%p-%r"
    ]
    groups = flatten([[
      split("@", source.name)[0],
      split("@", source.name)[1],
      source.type,
      ],
      { for i in var.post :
      "${i.name}@${i.target}" => lookup(i, "groups", []) }[source.name]
    ])

    extra_arguments = [
      "--extra-vars",
      "ansible_ssh_private_key_file=${var.config_folder}/.ssh/id_rsa",
      "--extra-vars",
      "openscap_report_name=${source.name}",
      "--extra-vars",
      "min_ansible_version=2.13.0",
      "--scp-extra-args", "'-O'",
      #"-vvv",
      # FIX: Forces the client transport layer to send active null-packets every 30 seconds
      "--ssh-extra-args", "-o ServerAliveInterval=30 -o ServerAliveCountMax=240"
    ]
  }

  provisioner "shell" {
    remote_folder = "/root"
    pause_after   = "20s"
    inline = [
      "date +%s > /tmp/post_build.txt",
      "sleep 20",
      "sync",
    ]
  }

  post-processors {
    post-processor "shell-local" {
      command = "bin/openscap.sh -f ansible/artifacts/${source.name}_image_scan_results.xml"
    }

    post-processor "shell-local" {
      environment_vars = ["BUILD_TIME=${local.build_time}"]
      command          = "bin/processor.sh --source_path post/${source.name}.qcow2"
    }

    post-processor "shell-local" {
      name = "jfrog_import"
      only = [
        for p in var.post :
        "qemu.${p.name}@${p.target}" if contains(values(p), "local_artifact")
      ]
      command = <<-CMD
        bin/validate-os.sh post/${source.name}.qcow2 || exit 1
        ${var.artifact.binary} rt upload '${var.artifact.source}/${source.name}.qcow2' \
          '${var.artifact.target}/${split("@", source.name)[0]}-x86_64-${local.build_time}.qcow2' \
          --url '${var.artifact.url}' \
          --user "$JFROG_USER" \
          --password "$JFROG_PASSWORD" \
          --fail-no-op=true \
          --build-name '${var.artifact.name}' \
          --build-number='${var.build_number}' \
          --target-props 'os=${split("@", source.name)[0]}' && \
          touch packer_cache/${source.name}.jfrog
      CMD
    }
  }
}
