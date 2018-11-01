#!/bin/bash -x

echo -n abc | sudo gmssl dgst -sm3 -engine sdf -engine_impl # -r
