"""SAST fixture: insecure deserialization (CWE-502)."""
import marshal
import pickle
import shelve

import jsonpickle
import numpy
import yaml


def load_session(blob: bytes):
    # tg-expect: SAST-030 | critical | CWE-502 | pickle.loads on untrusted bytes
    return pickle.loads(blob)


def load_config_default_loader(stream):
    # tg-expect: SAST-031 | critical | CWE-502 | yaml.load without a safe Loader
    return yaml.load(stream)


def load_config_unsafe_loader(stream):
    # tg-expect: SAST-032 | critical | CWE-502 | yaml.load with explicit unsafe yaml.Loader
    return yaml.load(stream, Loader=yaml.Loader)


def load_bytecode(blob: bytes):
    # tg-expect: SAST-033 | high | CWE-502 | marshal.loads on untrusted bytes
    return marshal.loads(blob)


def open_store(path: str):
    # tg-expect: SAST-034 | medium | CWE-502 | shelve.open (pickle-backed) on caller-controlled path
    return shelve.open(path)


def decode_payload(payload: str):
    # tg-expect: SAST-035 | critical | CWE-502 | jsonpickle.decode on untrusted input
    return jsonpickle.decode(payload)


def load_array(path: str):
    # tg-expect: SAST-036 | high | CWE-502 | numpy.load with allow_pickle=True
    return numpy.load(path, allow_pickle=True)
