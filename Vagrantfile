# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.box = "generic/alpine38"
  config.vm.provider :vmware_workstation do |v|
      v.vmx["memsize"] = "8192"
      v.vmx["numvcpus"] = "4"
      v.vmx["vhv.enable"] = "TRUE"
  end

  # Copy specific oc client compiled on alpine 3.8
  config.vm.provision "file", source: "./oc.tar.gz", destination: "/tmp/oc.tar.gz"

  config.vm.provision "shell", inline: <<-SHELL
IP="$(ip a show dev eth0 | grep -m1 inet | awk '{print $2}' | cut -d'/' -f1)"
echo "vagrant.$IP.xip.io" > /etc/hostname
hostname -F /etc/hostname
echo "$IP vagrant.$IP.xip.io vagrant" >> /etc/hosts
echo "tun" >> /etc/modules
modprobe tun
echo "Installing KVM..."
apk add qemu-system-x86_64 libvirt libvirt-daemon dbus qemu-img shadow 1>/dev/null 2>&1
rc-update add libvirtd default
rc-update add dbus default
usermod -aG libvirt vagrant
usermod -aG qemu vagrant
usermod -aG kvm vagrant
curl -sSL https://github.com/arnoSCC/docker-machine-kvm/releases/download/v0.10.0-3.8/docker-machine-driver-kvm-alpine3.8 -o /usr/local/bin/docker-machine-driver-kvm
chmod +x /usr/local/bin/docker-machine-driver-kvm
echo "kvm-intel" >> /etc/modules
modprobe kvm-intel
sed -ri 's/.?group\s?=\s?".+"/group = "kvm"/1' /etc/libvirt/qemu.conf
service dbus start
service libvirtd start
echo "Downloading minishift..."
curl -sSL https://github.com/minishift/minishift/releases/download/v1.33.0/minishift-1.33.0-linux-amd64.tgz | tar xz
mv minishift-1.33.0-linux-amd64/minishift /usr/local/bin/
rm -rf minishift-1.33.0-linux-amd64
echo "Extracting custom oc client..."
apk add gpgme 1>/dev/null 2>&1
mkdir -p /root/.minishift/cache/oc/v3.11.0/linux
tar xzf /tmp/oc.tar.gz
mv oc /root/.minishift/cache/oc/v3.11.0/linux/
rm -f /tmp/oc.tar.gz
echo "Downloading iso..."
curl -sSL https://github.com/minishift/minishift-b2d-iso/releases/download/v1.3.0/minishift-b2d.iso -o /root/minishift-b2d.iso
echo "Starting minishift... (it can take a while)"
minishift start --iso-url file:///root/minishift-b2d.iso  1>/dev/null 2>&1
minishift oc-env >> /etc/profile
eval $(minishift oc-env)
MINIP=$(virsh domifaddr minishift | grep vnet1 | awk '{print $4}' | cut -d'/' -f1)
echo "Installing nginx to access console..."
apk add nginx 1>/dev/null 2>&1
rc-update add nginx default
openssl req -x509 -nodes -newkey rsa:4096 -keyout /etc/nginx/conf.d/key.pem -out /etc/nginx/conf.d/cert.pem -days 365 -subj "/CN=$IP" 2>/dev/null
cat<<EOF>/etc/nginx/conf.d/default.conf
server {
  listen 8443 ssl http2 default_server;
  ssl_certificate         /etc/nginx/conf.d/cert.pem;
  ssl_certificate_key     /etc/nginx/conf.d/key.pem;

  location / {
    proxy_pass       https://${MINIP}:8443/;
    proxy_redirect   off;
    proxy_buffering  off;
    proxy_set_header Host            \\$host;
    proxy_set_header X-Real-IP       \\$remote_addr;
    proxy_set_header X-Forwarded-For \\$proxy_add_x_forwarded_for;
    proxy_set_header Accept-Encoding "";
    sub_filter_once  off;
    sub_filter_types *;
    sub_filter       ${MINIP} ${IP};
  }
}
EOF
service nginx start
echo "Monkey patching configuration to access console..."
oc login -u system:admin 1>/dev/null 2>&1
oc project openshift-web-console 1>/dev/null 2>&1
cat<<EOF>oauth-web-console.yml
apiVersion: oauth.openshift.io/v1
grantMethod: auto
kind: OAuthClient
metadata:
  name: openshift-web-console
redirectURIs:
- https://${IP}:8443/console/
- https://localhost:9000
EOF
oc apply -f oauth-web-console.yml 1>/dev/null 2>&1
rm -f oauth-web-console.yml
cat<<EOF>config-web-console.yml
apiVersion: v1
data:
  webconsole-config.yaml: |
    {"kind":"WebConsoleConfiguration","apiVersion":"webconsole.config.openshift.io/v1","servingInfo":{"bindAddress":"0.0.0.0:8443","bindNetwork":"tcp4","certFile":"/var/serving-cert/tls.crt","keyFile":"/var/serving-cert/tls.key","clientCA":"","namedCertificates":null,"maxRequestsInFlight":0,"requestTimeoutSeconds":0},"clusterInfo":{"consolePublicURL":"https://${IP}:8443/console/","masterPublicURL":"https://${IP}:8443","loggingPublicURL":"","metricsPublicURL":"","logoutPublicURL":"","adminConsolePublicURL":""},"features":{"inactivityTimeoutMinutes":0,"clusterResourceOverridesEnabled":false},"extensions":{"scriptURLs":[],"stylesheetURLs":[],"properties":null}}
kind: ConfigMap
metadata:
  name: webconsole-config
  namespace: openshift-web-console
EOF
oc apply -f config-web-console.yml 1>/dev/null 2>&1
rm -f oauth-web-console.yml
oc login -u developer 1>/dev/null 2>&1
echo "The server is accessible via web console at:"
echo "    https://$IP:8443/console"
echo " "
echo "    username: developer"
echo "    password: <any non-empy string>"
  SHELL

end
