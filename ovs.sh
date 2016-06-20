cd openvswitch-2.5.0/
make modules_install
/sbin/modprobe openvswitch
touch /usr/local/etc/ovs-vswitchd.conf
mkdir -p /usr/local/etc/openvswitch
rm -rf /usr/local/etc/openvswitch/conf.db
ovsdb-tool create /usr/local/etc/openvswitch/conf.db vswitchd/vswitch.ovsschema
ovsdb-server --remote=punix:/usr/local/var/run/openvswitch/db.sock \
--remote=db:Open_vSwitch,Open_vSwitch,manager_options \
--private-key=db:Open_vSwitch,SSL,private_key \
--certificate=db:Open_vSwitch,SSL,certificate \
--bootstrap-ca-cert=db:Open_vSwitch,SSL,ca_cert \
--pidfile --detach
ovs-vsctl --no-wait init
ovs-vswitchd --pidfile --detach
cd ..

cd nshkmod/
modprobe udp_tunnel
insmod ./nshkmod.ko
make

cd iproute2-3.19.0/
./configure
make & make install
