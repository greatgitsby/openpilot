#!/usr/bin/env bash

export OMP_NUM_THREADS=1
export MKL_NUM_THREADS=1
export NUMEXPR_NUM_THREADS=1
export OPENBLAS_NUM_THREADS=1
export VECLIB_MAXIMUM_THREADS=1
export SHOW_FPS=1
export FPS=60

if [ -z "$AGNOS_VERSION" ]; then
  export AGNOS_VERSION="14.3"
fi

export STAGING_ROOT="/data/safe_staging"
