# KV load balancer

## Description

This is a network function virtuliazation(NFV) research project, based on [OpenNetVM](https://github.com/sdnfv/openNetVM) for NFV support and [Intel DPDK](https://www.dpdk.org/) for bypassing kernel overhead, at GWU with Professor [Timothy Wood](http://faculty.cs.gwu.edu/timwood/). 

Last winter, I implemented a key-value load balancer as virtualizaed network function with hot key cache and lossy counting pre-cache.  Lossy counting was used for hotkey detection(with frequency threshold 0.2 and error rate 0.02, see this [paper](https://micvog.files.wordpress.com/2015/06/approximate_freq_count_over_data_streams_vldb_2002.pdf) for detail). Main idea is inspired by [NetKV](http://faculty.cs.gwu.edu/timwood/papers/16-ICAC-netkv.pdf), but we adapted the algorithem and design. The key-value data is stored in a cluster of Memcached servers and only handle UDP-based transmission for sake of similicity right now.

The testing enviorment on [CloudLab](https://cloudlab.us/), to which we specially want to say THANK YOU!

## Milestone

  - Implemented load balancing for Memcached set&get action. Balancing mechamism is based on hot-keys detected using lossy counting algothrim.
  - Implemented two layers of caching--one hotkey hash table, another "half-always on" skip list.
  - Max throughput for single key reaches 7M.

## In-Dev

As I continue work on this topic this spring, I intend to implement more complex features, adapt its architecture/algorithms, and maybe finish a research paper on it.
  
  - [x] Using DPDK api to create UDP packet
  - [x] Testing & using ONVM api to create UDP packet
  - [x] Handling Memcached Set action (especially data consistency)
  - [x] Two layers of caching
  - [x] Managing repliction with DHT
  - [ ] Impelementing a pressure testing tool for Memcached
  - [ ] Adapting lossy counting (weighted)

## Todo

  - Self-adaptive lossy counting
  - Basic fault tolerance without affecting performance(low priority)
  - TCP-based transmisson (low priority)

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
- **kvlb_nf**: the implementation of our key-value load balancer.
- **LC-experiments**: serval experiments on lossy counting.
- **udp-test-client**： a demo used to test ONVM working enviorment.

----
Code is not up to date. I will publish a paper within this year, and will release code then.
