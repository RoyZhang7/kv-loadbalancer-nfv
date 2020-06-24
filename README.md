# A NFV-based KV load balancer for Memcached

## Description
**This project is abandoned as I am pursuing Ph.D. in another field**

This is a network function virtuliazation(NFV) research project, based on [OpenNetVM](https://github.com/sdnfv/openNetVM) as NFV platform, at GWU with Professor [Timothy Wood](http://faculty.cs.gwu.edu/timwood/). 

I currently co-op with memebers in GW NFV group on another big project, which was inspired by this repo a lot. It is a L7 stateless load balancer in L4 level--handling Redis load based on TCP-splicing, along with a Redis "NFVlized" solution and a availability solution during Redis migration using NFV.

Before my graduation from master's degree, I firstly implemented a key-value load balancer as a virtualizaed network function with hot key cache and lossy counting pre-cache.  Lossy counting was used for hotkey detection(with frequency threshold 0.2 and error rate 0.02, see this [paper](https://micvog.files.wordpress.com/2015/06/approximate_freq_count_over_data_streams_vldb_2002.pdf)). Main idea is inspired by [NetKV](http://faculty.cs.gwu.edu/timwood/papers/16-ICAC-netkv.pdf). Later, I prposed a new balancer design with skip list as the second layer cache and implemented set action mechanism. The max throughput of set action reached 7M/sec.

The testing and development enviorment on [CloudLab](https://cloudlab.us/), to which we specially want to say THANK YOU!

## Milestone

  1. Current packet-level stateless L7 LB
  
      on going.
  
  2. Old project
      - Implemented load balancing for Memcached set&get action. Balancing mechamism is based on hot-keys detected using lossy counting algothrim.
      - Implemented two layers of caching--one hotkey hash table, another "half-always on" skip list.
      - Max throughput for single key reaches 7M.
  
  
    

## Features of old KVLB
  
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

**May not available for public usage in a long time.**

I will provide intruction if this research get published someday.

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
