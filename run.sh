#!/bin/bash

#起1个线程足矣，多个线程可能会导致缓存访问问题
./run_service.py --thrift-threads=1