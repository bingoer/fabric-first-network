## Build Your First Network (BYFN)

The directions for using this are documented in the Hyperledger Fabric
["Build Your First Network"](http://hyperledger-fabric.readthedocs.io/en/latest/build_network.html) tutorial.

*NOTE:* After navigating to the documentation, choose the documentation version that matches your version of Fabric

## Use fabric-ca-server Build Your First Network (BYFN)

- step 1：Generate Artifacts use fabric-ca-server

```bash
./byfn.sh generateCA
```

- step 2：Create the network

```bash
./byfn.sh up
```

- step 3：Clear the network

```bash
./byfn.sh down
```