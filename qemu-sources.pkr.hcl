source "qemu" "enterprise_linux" {
  qemu_binary          = "/usr/libexec/qemu-kvm"
  disk_size            = "${var.size}G"
  format               = "qcow2"
  accelerator          = "kvm"
  http_bind_address    = "127.0.0.1"
  ssh_username         = "root"
  ssh_private_key_file = "${var.config_folder}/.ssh/id_rsa"
  ssh_timeout          = "2h"
  ssh_handshake_attempts = 1000
  ssh_wait_timeout     = "30m"
  headless             = true
  net_device           = "virtio-net"
  disk_interface       = "virtio"
  disk_cache           = "writethrough"

  boot_wait            = "10s"
  shutdown_command     = "shutdown -P now"
  shutdown_timeout     = "15m"

  cpus                 = 4
  memory               = 8192
  vnc_bind_address     = var.vnc_bind_address

  qemuargs = [
    ["-cpu", var.cpu],
    ["-netdev", "user,hostfwd=tcp:127.0.0.1:{{ .SSHHostPort }}-:22,id=user.0"],
    ["-serial","unix:packer_cache/serial/{{ .SSHHostPort }}.sock,server,nowait"]
  ]
}