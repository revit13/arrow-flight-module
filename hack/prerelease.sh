#!/usr/bin/env bash
# Copyright 2020 IBM Corp.
# SPDX-License-Identifier: Apache-2.0

: ${TAG:=0.0.0}
: ${TOOLBIN:=./hack/tools/bin}

${TOOLBIN}/yq eval --inplace ".spec.chart.name = \"ghcr.io/fybrik/arrow-flight-module-chart:$TAG\"" ./module.yaml
