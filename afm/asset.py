#
# Copyright 2020 IBM Corp.
# SPDX-License-Identifier: Apache-2.0
#
import os

from afm.config import Config
from afm.pep import registry, consolidate_actions
from afm.filesystems.s3 import s3filesystem_from_config
from afm.filesystems.httpfs import httpfs_from_config
from afm.flight.flight import flight_from_config

from pyarrow.fs import LocalFileSystem

def asset_from_config(config: Config, asset_name: str, partition_path=None, capability="", write_mode=""):
    connection_type = config.connection_type(asset_name, capability)
    if connection_type in ['s3', 'httpfs', 'localfs']:
        return FileSystemAsset(config, asset_name, partition_path, capability, write_mode)
    elif connection_type == 'flight':
        return FlightAsset(config, asset_name, capability=capability, write_mode=write_mode)
    raise ValueError(
        "Unsupported connection type: {}".format(config.connection_type))

class Asset:
    def __init__(self, config: Config, asset_name: str, partition_path=None, capability="", write_mode=""):
        asset_config = config.for_asset(asset_name, capability=capability)
        self._config = asset_config
        self._actions = Asset._actions_for_asset(asset_config)
        self._format = asset_config.get("format")
        self._write_mode = write_mode
        if partition_path:
            self._path = partition_path
        else:
            self._path = asset_config.get("path")
        self._name = asset_config.get("name")

    def add_action(self, action):
        self._actions.insert(0, action)

    @property
    def actions(self):
        return self._actions

    @property
    def name(self):
        return self._name

    @property
    def format(self):
        return self._format

    @property
    def path(self):
        return self._path

    @property
    def connection_type(self):
        return self._config['connection']['type']

    @property
    def write_mode(self):
        return self._write_mode

    @staticmethod
    def _actions_for_asset(asset_config: dict):
        def build_action(x):
            cls = registry[x["action"]]
            return cls(description=x["description"], columns=x.get("columns"), options=x.get("options"))

        transformations = asset_config.get("transformations")
        if not transformations:
            transformations = []
        # Create a list of Action objects from the transformations configuration
        actions = [build_action(x) for x in transformations]
        # Consolidate identical actions to keep the asset.actions efficient
        return consolidate_actions(actions)

class FileSystemAsset(Asset):
    def __init__(self, config: Config, asset_name: str, partition_path=None, capability="", write_mode=""):
        super().__init__(config, asset_name, partition_path, capability, write_mode)
        self._filesystem = FileSystemAsset._filesystem_for_asset(self._config)

    @staticmethod
    def _filesystem_for_asset(asset_config: dict):
        connection = asset_config['connection']
        connection_type = connection['type']
        if connection_type == "s3":
            return s3filesystem_from_config(connection["s3"], asset_config['name'])
        elif connection_type == "localfs":
            return LocalFileSystem()
        elif connection_type == "httpfs":
            return httpfs_from_config()
        raise ValueError(
            "Unsupported connection type: {}".format(connection_type))

    @property
    def filesystem(self):
        return self._filesystem

class FlightAsset(Asset):
    def __init__(self, config: Config, asset_name: str, capability="", write_mode=""):
        super().__init__(config, asset_name, capability=capability, write_mode=write_mode)
        self._flight = flight_from_config(self._config['connection']['flight'])

    @property
    def flight(self):
        return self._flight
