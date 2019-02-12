# KV load balancer

## Description

This is a network function virtuliazation(NFV) research project, based on [OpenNetVM](https://github.com/sdnfv/openNetVM) for NFV support and [Intel DPDK](https://www.dpdk.org/) for bypassing kernel overhead, at GWU with Professor [Timothy Wood](http://faculty.cs.gwu.edu/timwood/). 

I implemented a key-value load balancer as virtualizaed network function, with hot key cache and lossy counting pre-cache using lossy counting for hotkey detection(with frequency threshold 0.2 and error rate 0.02, see this [paper](https://micvog.files.wordpress.com/2015/06/approximate_freq_count_over_data_streams_vldb_2002.pdf) for detail). Main idea is inspired by a paper
[NetKV](http://faculty.cs.gwu.edu/timwood/papers/16-ICAC-netkv.pdf), but we adapted the algorithem and design. The Key-value data is stored in a cluster of Memcached servers and only handle Memcached GET action for sake of similicity of research.

The testing enviorment on [CloudLab](https://cloudlab.us/), to which we specially want to say THANK YOU!

## In-Dev

As I continue work on this topic, I am intended to implement more complex features, adapt its architecture/algorithms, and maybe finish a research paper on it.

- Using DPDK api to create UDP packet
- Testing ONVM api of creating UDP packet
- Handling Memcached Set action (especially data consistency)
- Managing repliction with DHT
- Adapting lossy counting (weighted)

## Todo

- Adapting lossy counting (self-adaptive)
- Basic fault tolerance without affecting performance
- TCP stack

## Project structure

``` bash
Mode     Name
----     ----
d-----   benchmark
d-----   kvlb_nf
d-----   LC-experiments
d-----   udp-test-client
```

- **benchmark**: the tool we implemented for stress testing.
- **kvlb_nf**: the implementation of our key-value load balancer using OpenNetVM and DPDK.
- **LC-experiments**: serval experiments on lossy counting
- **udp-test-client**： a demo used for testing ONVM working enviorment.
