variable "cpus" {
  type    = number
  default = 2
}

variable "cpu" {
  type    = string
  default = "host"
}

variable "format" {
  type    = string
  default = "qcow2"
}

variable "memory" {
  type    = number
  default = 4096
}

variable "size" {
  type    = number
  default = 75
}

variable "build_number" {
  type    = string
  default = "0"
}

variable "pwd" {
  type    = string
  default = env("PWD")
}

variable "config_folder" {
  type    = string
  default = "cfg"
}

variable "ntp_servers" {
  type    = string
  default = null
}

variable "vnc_bind_address" {
  type    = string
  default = "127.0.0.1"
}

variable "seed_grub_pass" {
  type    = string
  default = env("SEED_GRUB_PASS")
}

variable "git_commit" {
  type    = string
  default = env("GIT_COMMIT")
}

variable "git_branch" {
  type    = string
  default = env("GIT_BRANCH")
}

variable "default_tags" {
  default = {}
}

variable "it" {
  default = null
}

variable "prep" {
  default = []
}

variable "post" {
  default = null
}

variable "artifact" {
  type = object({
    binary       = string
    source       = string
    target       = string
    url          = string
    name         = string
    env_exclude  = string
    target_props = string
    server_id    = string
  })
  default = {
    binary       = "/usr/bin/jfrog"
    source       = "post"
    target       = ""
    url          = ""
    name         = ""
    env_exclude  = null
    target_props = ""
    server_id    = ""
  }
}
