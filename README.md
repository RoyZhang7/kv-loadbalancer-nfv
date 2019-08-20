# A KV load balancer (Memcached)

## Description

This is a network function virtuliazation(NFV) research project, based on [OpenNetVM](https://github.com/sdnfv/openNetVM) for NFV support and [Intel DPDK](https://www.dpdk.org/), at GWU with Professor [Timothy Wood](http://faculty.cs.gwu.edu/timwood/). 

Before my graduation from GW, I firstly implemented a key-value load balancer as a virtualizaed network function with hot key cache and lossy counting pre-cache.  Lossy counting was used for hotkey detection(with frequency threshold 0.2 and error rate 0.02, see this [paper](https://micvog.files.wordpress.com/2015/06/approximate_freq_count_over_data_streams_vldb_2002.pdf)). Main idea is inspired by [NetKV](http://faculty.cs.gwu.edu/timwood/papers/16-ICAC-netkv.pdf). Later, I prposed a new balancer design with skip list as the second layer cache and implemented set action mechanism. The max throughput of set action reached 7M/sec.

After graduation, I still co-op with memebers in GW NFV group on a brand new TCP-splicer-like L4+L7 proxy+LB, which inspired on this repo a lot.

The testing enviorment on [CloudLab](https://cloudlab.us/), to which we specially want to say THANK YOU!

## Milestone

  1. Old LB
    - Implemented load balancing for Memcached set&get action. Balancing mechamism is based on hot-keys detected using lossy counting algothrim.
    - Implemented two layers of caching--one hotkey hash table, another "half-always on" skip list.
    - Max throughput for single key reaches 7M.
  
  2. New L4 Proxy + LB
    

## Features of old KVLB

As I continue work on this topic this spring, I intend to implement more complex features, adapt its architecture/algorithms, and maybe finish a research paper on it.
  
  - [x] Using DPDK api to create UDP packet
  - [x] Testing & using ONVM api to create UDP packet
  - [x] Handling Memcached Set action //data consistency
  - [x] Two layers of caching
  - [x] Managing repliction with DHT


## Potential Direction (low priority)

  - Self-adaptive lossy counting
  - Basic fault tolerance without affecting performance
  - TCP-based transmisson
  - Propose weighted lossy counting
  - Impelementing a pressure testing tool for Memcached

## Usage

**Not available for public user yet.**

I will provide intruction on other system/platform on the planned releasing.

This project requires installation of OpenNetVM(including DPDK). The easiest way to use it is creating a cluster with CloudLab profile.(strict to authroized academic user in US only).

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
Code is not up to date. I will publish a paper related to this project within this year, however, thie part of code may not be released since we have a brand new repo.
