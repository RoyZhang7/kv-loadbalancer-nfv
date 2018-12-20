# KV load balancer

## Description

This is a network function virtuliazation(NFV) research project, based on [OpenNetVM](https://github.com/sdnfv/openNetVM) and DPDK api to bypass linux kernel overhead.

We implemented a key-value load balancer with cache and pre-cache on hotkeys detected by lossying counting. Main idea is inspired by a paper
[NetKV](http://faculty.cs.gwu.edu/timwood/papers/16-ICAC-netkv.pdf), but we adapted the algorithem and design.

The Key-value data is stored in a cluster of Memcached servers and only about GET action for sake of similicity of research. The testing enviorment on [CloudLab](https://cloudlab.us/), to which we want to say THANKYOU.

## Project structure

``` bash
Mode     Name
----     ----
d-----   benchmark
d-----   demo_no_onvm
d-----   kvlb_nf
d-----   udp-test-client
```

- **benchmark**: the tool we implemented for stress testing.
- **demo_no_onvm**: a demo showing result of a single round of lossy counting.
- **kvlb_nf**: the implementation of our key-value load balancer using OpenNetVM and DPDK.
- **udp-test-client**： a script used for setting up ONVM working enviorment.