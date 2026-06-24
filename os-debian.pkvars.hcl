# Creates initial prep image(s) using the Debian genericcloud base image.
# No installer/preseed needed - boots directly from the cloud image.
prep = [
  {
    name         = "debian12"
    iso_path     = "debian-iso-baseimage/debian-12-generic-amd64-20251112-2294.qcow2"
    iso_checksum = "6b2c9b6bd9c3f691e4df1fdba7e7d0d7a7bbd015981c946742fcd99c8d8039a6" #"5da221d8f7434ee86145e78a2c60ca45eb4ef8296535e04f6f333193225792aa8ceee3df6aea2b4ee72d6793f7312308a8b0c6a1c7ed4c7c730fa7bda1bc665f"
    ks_tmpl      = ""
    boot_command = ["<esc><wait>auto url=http://{{ .HTTPIP }}:{{ .HTTPPort }}/preseed.cfg<enter>"]
  }
]

# Creates image(s) using prep images as source, applies Ansible modifications and publishes to Artifactory.
post = [
  {
    name   = "debian12"
    target = "local_artifact"
    groups = ["debian12", "debian", "local_artifact"]
  }
]
