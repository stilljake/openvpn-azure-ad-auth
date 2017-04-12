# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|

  config.vm.box = "minimal/trusty64"

  config.vm.provision "shell", inline: <<-SHELL
    apt-get update
    apt-get install -y build-essential libssl-dev libffi-dev python-dev libyaml-dev curl
    curl -O https://bootstrap.pypa.io/get-pip.py && python get-pip.py
    pip install --upgrade urllib3[secure]
    pip install --upgrade -r /vagrant/requirements.txt
  SHELL
end
